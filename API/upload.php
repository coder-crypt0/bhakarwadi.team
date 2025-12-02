<?php
require_once 'config.php';
require_once 'database.php';

header("Access-Control-Allow-Origin: {$_ENV['CORS_ORIGIN']}");
header("Access-Control-Allow-Methods: POST, GET, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key");
header("Access-Control-Max-Age: 3600");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Rate limiting
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (!checkRateLimit($client_ip, 'upload', 20, 300)) { // 20 requests per 5 minutes
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'error' => 'Rate limit exceeded. Please try again later.'
    ]);
    exit();
}

// Verify API key
$api_key = $_SERVER['HTTP_X_API_KEY'] ?? '';
if ($api_key !== $_ENV['API_SECRET_KEY']) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'error' => 'Invalid API key'
    ]);
    exit();
}

$database = new Database();
$pdo = $database->getConnection();

// Upload configuration
$upload_config = [
    'max_file_size' => 50 * 1024 * 1024, // 50MB
    'allowed_types' => [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'text/plain', 'application/pdf',
        'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/zip', 'application/x-zip-compressed',
        'application/json', 'text/csv'
    ],
    'upload_dir' => '/uploads/',
    'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'json', 'csv']
];

/**
 * Authenticate user session
 */
function authenticateUser($pdo, $session_token) {
    if (empty($session_token)) {
        return null;
    }
    
    $stmt = $pdo->prepare("
        SELECT s.user_id, u.username, u.display_name, u.status
        FROM user_sessions s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.session_token = ? AND s.is_active = TRUE AND s.expires_at > NOW()
    ");
    $stmt->execute([$session_token]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

/**
 * Upload file
 */
function uploadFile($pdo, $user_id, $file_data, $config) {
    try {
        // Validate file data
        if (!isset($file_data['tmp_name']) || !is_uploaded_file($file_data['tmp_name'])) {
            return [
                'success' => false,
                'error' => 'No file uploaded or invalid file'
            ];
        }
        
        $original_filename = $file_data['name'];
        $tmp_name = $file_data['tmp_name'];
        $file_size = $file_data['size'];
        $file_error = $file_data['error'];
        
        // Check for upload errors
        if ($file_error !== UPLOAD_ERR_OK) {
            $error_messages = [
                UPLOAD_ERR_INI_SIZE => 'File exceeds php.ini upload_max_filesize',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds form MAX_FILE_SIZE',
                UPLOAD_ERR_PARTIAL => 'File only partially uploaded',
                UPLOAD_ERR_NO_FILE => 'No file uploaded',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
                UPLOAD_ERR_EXTENSION => 'Upload stopped by extension'
            ];
            
            return [
                'success' => false,
                'error' => 'Upload error: ' . ($error_messages[$file_error] ?? 'Unknown error')
            ];
        }
        
        // Validate file size
        if ($file_size > $config['max_file_size']) {
            return [
                'success' => false,
                'error' => 'File too large. Maximum size: ' . ($config['max_file_size'] / 1024 / 1024) . 'MB'
            ];
        }
        
        if ($file_size == 0) {
            return [
                'success' => false,
                'error' => 'Empty file not allowed'
            ];
        }
        
        // Validate file extension
        $file_extension = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));
        if (!in_array($file_extension, $config['allowed_extensions'])) {
            return [
                'success' => false,
                'error' => 'File type not allowed. Allowed: ' . implode(', ', $config['allowed_extensions'])
            ];
        }
        
        // Detect MIME type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $tmp_name);
        finfo_close($finfo);
        
        // Validate MIME type
        if (!in_array($mime_type, $config['allowed_types'])) {
            return [
                'success' => false,
                'error' => 'File MIME type not allowed: ' . $mime_type
            ];
        }
        
        // Generate secure filename
        $file_id = bin2hex(random_bytes(16));
        $secure_filename = $file_id . '.' . $file_extension;
        
        // Create upload directory if it doesn't exist
        $upload_dir = __DIR__ . $config['upload_dir'];
        if (!is_dir($upload_dir)) {
            if (!mkdir($upload_dir, 0755, true)) {
                return [
                    'success' => false,
                    'error' => 'Failed to create upload directory'
                ];
            }
        }
        
        // Create user subdirectory
        $user_upload_dir = $upload_dir . substr($user_id, 0, 2) . '/';
        if (!is_dir($user_upload_dir)) {
            if (!mkdir($user_upload_dir, 0755, true)) {
                return [
                    'success' => false,
                    'error' => 'Failed to create user upload directory'
                ];
            }
        }
        
        $file_path = $user_upload_dir . $secure_filename;
        
        // Move uploaded file
        if (!move_uploaded_file($tmp_name, $file_path)) {
            return [
                'success' => false,
                'error' => 'Failed to save uploaded file'
            ];
        }
        
        // Calculate file hash for integrity
        $file_hash = hash_file('sha256', $file_path);
        
        // Check if file already exists (by hash)
        $stmt = $pdo->prepare("
            SELECT file_id, original_filename 
            FROM file_uploads 
            WHERE user_id = ? AND file_hash = ? AND status = 'uploaded'
        ");
        $stmt->execute([$user_id, $file_hash]);
        $existing_file = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($existing_file) {
            // Remove the newly uploaded duplicate
            unlink($file_path);
            
            return [
                'success' => true,
                'message' => 'File already exists (duplicate)',
                'file_id' => $existing_file['file_id'],
                'original_filename' => $existing_file['original_filename'],
                'is_duplicate' => true
            ];
        }
        
        // Additional security checks for images
        if (strpos($mime_type, 'image/') === 0) {
            // Verify image integrity
            $image_info = getimagesize($file_path);
            if (!$image_info) {
                unlink($file_path);
                return [
                    'success' => false,
                    'error' => 'Invalid or corrupted image file'
                ];
            }
            
            // Check image dimensions (optional)
            $max_width = 4000;
            $max_height = 4000;
            if ($image_info[0] > $max_width || $image_info[1] > $max_height) {
                unlink($file_path);
                return [
                    'success' => false,
                    'error' => "Image too large. Maximum dimensions: {$max_width}x{$max_height}"
                ];
            }
        }
        
        // Store file information in database
        $stmt = $pdo->prepare("
            INSERT INTO file_uploads (
                file_id, user_id, original_filename, stored_filename, 
                file_path, file_size, mime_type, file_hash, 
                status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'uploaded', NOW())
        ");
        
        $relative_path = $config['upload_dir'] . substr($user_id, 0, 2) . '/' . $secure_filename;
        
        if ($stmt->execute([
            $file_id, $user_id, $original_filename, $secure_filename,
            $relative_path, $file_size, $mime_type, $file_hash
        ])) {
            return [
                'success' => true,
                'message' => 'File uploaded successfully',
                'file_id' => $file_id,
                'original_filename' => $original_filename,
                'file_size' => $file_size,
                'mime_type' => $mime_type,
                'upload_date' => date('c')
            ];
        } else {
            // Cleanup file if database insert failed
            unlink($file_path);
            return [
                'success' => false,
                'error' => 'Failed to store file information'
            ];
        }
        
    } catch (Exception $e) {
        error_log("Upload file error: " . $e->getMessage());
        
        // Cleanup file on error
        if (isset($file_path) && file_exists($file_path)) {
            unlink($file_path);
        }
        
        return [
            'success' => false,
            'error' => 'File upload failed'
        ];
    }
}

/**
 * Download file
 */
function downloadFile($pdo, $user_id, $file_id) {
    try {
        // Get file information
        $stmt = $pdo->prepare("
            SELECT f.*, 
                   CASE WHEN f.user_id = ? THEN TRUE ELSE FALSE END as is_owner,
                   EXISTS(
                       SELECT 1 FROM messages m 
                       WHERE m.file_id = ? 
                         AND (m.sender_id = ? OR m.receiver_id = ?)
                         AND m.deleted_at IS NULL
                   ) as has_access
            FROM file_uploads f
            WHERE f.file_id = ? AND f.status = 'uploaded'
        ");
        $stmt->execute([$user_id, $file_id, $user_id, $user_id, $file_id]);
        $file_info = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$file_info) {
            return [
                'success' => false,
                'error' => 'File not found',
                'http_code' => 404
            ];
        }
        
        // Check access permissions
        if (!$file_info['is_owner'] && !$file_info['has_access']) {
            return [
                'success' => false,
                'error' => 'Access denied',
                'http_code' => 403
            ];
        }
        
        $file_path = __DIR__ . $file_info['file_path'];
        
        // Check if file exists on filesystem
        if (!file_exists($file_path)) {
            // Mark file as missing in database
            $stmt = $pdo->prepare("
                UPDATE file_uploads 
                SET status = 'missing', updated_at = NOW()
                WHERE file_id = ?
            ");
            $stmt->execute([$file_id]);
            
            return [
                'success' => false,
                'error' => 'File not found on server',
                'http_code' => 404
            ];
        }
        
        // Update download count
        $stmt = $pdo->prepare("
            UPDATE file_uploads 
            SET download_count = download_count + 1, last_accessed = NOW()
            WHERE file_id = ?
        ");
        $stmt->execute([$file_id]);
        
        return [
            'success' => true,
            'file_info' => $file_info,
            'file_path' => $file_path
        ];
        
    } catch (PDOException $e) {
        error_log("Download file error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to access file',
            'http_code' => 500
        ];
    }
}

/**
 * Delete file
 */
function deleteFile($pdo, $user_id, $file_id) {
    try {
        // Get file information and check ownership
        $stmt = $pdo->prepare("
            SELECT file_path, user_id, status
            FROM file_uploads
            WHERE file_id = ? AND user_id = ?
        ");
        $stmt->execute([$file_id, $user_id]);
        $file_info = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$file_info) {
            return [
                'success' => false,
                'error' => 'File not found or access denied'
            ];
        }
        
        if ($file_info['status'] === 'deleted') {
            return [
                'success' => false,
                'error' => 'File already deleted'
            ];
        }
        
        // Check if file is referenced in any messages
        $stmt = $pdo->prepare("
            SELECT COUNT(*) 
            FROM messages 
            WHERE file_id = ? AND deleted_at IS NULL
        ");
        $stmt->execute([$file_id]);
        $message_count = $stmt->fetchColumn();
        
        if ($message_count > 0) {
            return [
                'success' => false,
                'error' => 'Cannot delete file: it is referenced in active messages'
            ];
        }
        
        // Start transaction
        $pdo->beginTransaction();
        
        try {
            // Mark file as deleted in database
            $stmt = $pdo->prepare("
                UPDATE file_uploads 
                SET status = 'deleted', updated_at = NOW()
                WHERE file_id = ?
            ");
            $stmt->execute([$file_id]);
            
            // Delete physical file
            $file_path = __DIR__ . $file_info['file_path'];
            if (file_exists($file_path)) {
                unlink($file_path);
            }
            
            $pdo->commit();
            
            return [
                'success' => true,
                'message' => 'File deleted successfully'
            ];
            
        } catch (Exception $e) {
            $pdo->rollBack();
            throw $e;
        }
        
    } catch (PDOException $e) {
        error_log("Delete file error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to delete file'
        ];
    }
}

/**
 * Get user files
 */
function getUserFiles($pdo, $user_id, $limit = 20, $offset = 0) {
    try {
        $limit = min(max(1, (int)$limit), 100); // Max 100 files
        $offset = max(0, (int)$offset);
        
        $stmt = $pdo->prepare("
            SELECT file_id, original_filename, file_size, mime_type, 
                   download_count, created_at, last_accessed
            FROM file_uploads
            WHERE user_id = ? AND status = 'uploaded'
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        ");
        $stmt->execute([$user_id, $limit, $offset]);
        $files = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get total count
        $stmt = $pdo->prepare("
            SELECT COUNT(*) 
            FROM file_uploads
            WHERE user_id = ? AND status = 'uploaded'
        ");
        $stmt->execute([$user_id]);
        $total_count = $stmt->fetchColumn();
        
        return [
            'success' => true,
            'files' => $files,
            'pagination' => [
                'total' => (int)$total_count,
                'limit' => $limit,
                'offset' => $offset,
                'has_more' => ($offset + $limit) < $total_count
            ]
        ];
        
    } catch (PDOException $e) {
        error_log("Get user files error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to retrieve files'
        ];
    }
}

/**
 * Rate limiting function
 */
function checkRateLimit($client_ip, $action, $limit, $window) {
    $rate_limit_file = "/tmp/rate_limit_{$action}_{$client_ip}.txt";
    $current_time = time();
    
    if (file_exists($rate_limit_file)) {
        $data = json_decode(file_get_contents($rate_limit_file), true);
        if ($data && isset($data['count'], $data['window_start'])) {
            if ($current_time - $data['window_start'] < $window) {
                if ($data['count'] >= $limit) {
                    return false;
                }
                $data['count']++;
            } else {
                $data = ['count' => 1, 'window_start' => $current_time];
            }
        } else {
            $data = ['count' => 1, 'window_start' => $current_time];
        }
    } else {
        $data = ['count' => 1, 'window_start' => $current_time];
    }
    
    file_put_contents($rate_limit_file, json_encode($data));
    return true;
}

// Main request handler
try {
    $request_method = $_SERVER['REQUEST_METHOD'];
    
    // Get session token
    $session_token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $session_token = str_replace('Bearer ', '', $session_token);
    
    // Authenticate user
    $current_user = authenticateUser($pdo, $session_token);
    if (!$current_user) {
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'error' => 'Authentication required'
        ]);
        exit();
    }
    
    $user_id = $current_user['user_id'];
    $action = $_GET['action'] ?? '';
    
    switch ($request_method) {
        case 'POST':
            if ($action === 'upload') {
                if (!isset($_FILES['file'])) {
                    $response = [
                        'success' => false,
                        'error' => 'No file provided'
                    ];
                } else {
                    $response = uploadFile($pdo, $user_id, $_FILES['file'], $upload_config);
                }
                header('Content-Type: application/json');
                echo json_encode($response, JSON_PRETTY_PRINT);
            } else {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => 'Invalid action for POST request'
                ]);
            }
            break;
            
        case 'GET':
            switch ($action) {
                case 'download':
                    $file_id = $_GET['file_id'] ?? '';
                    if (empty($file_id)) {
                        http_response_code(400);
                        echo json_encode([
                            'success' => false,
                            'error' => 'File ID is required'
                        ]);
                    } else {
                        $result = downloadFile($pdo, $user_id, $file_id);
                        if (!$result['success']) {
                            http_response_code($result['http_code'] ?? 400);
                            header('Content-Type: application/json');
                            echo json_encode([
                                'success' => false,
                                'error' => $result['error']
                            ]);
                        } else {
                            $file_info = $result['file_info'];
                            $file_path = $result['file_path'];
                            
                            // Set appropriate headers for file download
                            header('Content-Type: ' . $file_info['mime_type']);
                            header('Content-Length: ' . $file_info['file_size']);
                            header('Content-Disposition: attachment; filename="' . $file_info['original_filename'] . '"');
                            header('Cache-Control: no-cache, must-revalidate');
                            header('Expires: 0');
                            
                            // Stream file to output
                            readfile($file_path);
                        }
                    }
                    break;
                    
                case 'list':
                    $limit = $_GET['limit'] ?? 20;
                    $offset = $_GET['offset'] ?? 0;
                    $response = getUserFiles($pdo, $user_id, $limit, $offset);
                    header('Content-Type: application/json');
                    echo json_encode($response, JSON_PRETTY_PRINT);
                    break;
                    
                default:
                    http_response_code(400);
                    header('Content-Type: application/json');
                    echo json_encode([
                        'success' => false,
                        'error' => 'Invalid action for GET request'
                    ]);
                    break;
            }
            break;
            
        case 'DELETE':
            $file_id = $_GET['file_id'] ?? '';
            if (empty($file_id)) {
                $response = [
                    'success' => false,
                    'error' => 'File ID is required'
                ];
            } else {
                $response = deleteFile($pdo, $user_id, $file_id);
            }
            header('Content-Type: application/json');
            echo json_encode($response, JSON_PRETTY_PRINT);
            break;
            
        default:
            http_response_code(405);
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'error' => 'Method not allowed'
            ]);
            break;
    }
    
} catch (Exception $e) {
    error_log("Upload API error: " . $e->getMessage());
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error'
    ]);
}
?>
