<?php
require_once 'config.php';
require_once 'database.php';

header('Content-Type: application/json');
header("Access-Control-Allow-Origin: {$_ENV['CORS_ORIGIN']}");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key");
header("Access-Control-Max-Age: 3600");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Rate limiting
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (!checkRateLimit($client_ip, 'messages', 100, 300)) { // 100 requests per 5 minutes
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
 * Send a message
 */
function sendMessage($pdo, $sender_id, $data) {
    try {
        // Validate required fields
        $required_fields = ['receiver_id', 'content'];
        foreach ($required_fields as $field) {
            if (empty($data[$field])) {
                return [
                    'success' => false,
                    'error' => "Missing required field: {$field}"
                ];
            }
        }
        
        $receiver_id = trim($data['receiver_id']);
        $content = trim($data['content']);
        $message_type = $data['message_type'] ?? 'text';
        $encryption_key = $data['encryption_key'] ?? '';
        $file_id = $data['file_id'] ?? null;
        
        // Validate message type
        $allowed_types = ['text', 'file', 'image', 'system'];
        if (!in_array($message_type, $allowed_types)) {
            return [
                'success' => false,
                'error' => 'Invalid message type. Allowed: text, file, image, system'
            ];
        }
        
        // Validate content length
        if (strlen($content) > 4000) {
            return [
                'success' => false,
                'error' => 'Message content too long (max 4000 characters)'
            ];
        }
        
        // Check if receiver exists and is active
        $stmt = $pdo->prepare("
            SELECT user_id, username, status 
            FROM users 
            WHERE user_id = ? AND status != 'deleted'
        ");
        $stmt->execute([$receiver_id]);
        $receiver = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$receiver) {
            return [
                'success' => false,
                'error' => 'Receiver not found or account deleted'
            ];
        }
        
        // Check if trying to send to self
        if ($sender_id === $receiver_id) {
            return [
                'success' => false,
                'error' => 'Cannot send message to yourself'
            ];
        }
        
        // Validate file reference if file message
        if ($message_type === 'file' || $message_type === 'image') {
            if (empty($file_id)) {
                return [
                    'success' => false,
                    'error' => 'File ID is required for file/image messages'
                ];
            }
            
            $stmt = $pdo->prepare("
                SELECT file_id, original_filename, file_size 
                FROM file_uploads 
                WHERE file_id = ? AND user_id = ? AND status = 'uploaded'
            ");
            $stmt->execute([$file_id, $sender_id]);
            $file = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$file) {
                return [
                    'success' => false,
                    'error' => 'File not found or not accessible'
                ];
            }
        }
        
        // Generate message ID
        $message_id = bin2hex(random_bytes(16));
        
        // Insert message
        $stmt = $pdo->prepare("
            INSERT INTO messages (
                message_id, sender_id, receiver_id, content, message_type, 
                encryption_key, file_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
        ");
        
        if ($stmt->execute([
            $message_id, $sender_id, $receiver_id, $content, 
            $message_type, $encryption_key, $file_id
        ])) {
            // Update last activity for both users
            $stmt = $pdo->prepare("
                UPDATE users 
                SET last_active = NOW()
                WHERE user_id IN (?, ?)
            ");
            $stmt->execute([$sender_id, $receiver_id]);
            
            return [
                'success' => true,
                'message' => 'Message sent successfully',
                'message_id' => $message_id,
                'timestamp' => date('c')
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Failed to send message'
            ];
        }
        
    } catch (PDOException $e) {
        error_log("Send message error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Database error occurred'
        ];
    }
}

/**
 * Get messages (conversation)
 */
function getMessages($pdo, $user_id, $other_user_id, $limit = 50, $offset = 0, $before_message_id = null) {
    try {
        $limit = min(max(1, (int)$limit), 100); // Max 100 messages
        $offset = max(0, (int)$offset);
        
        // Validate other user exists
        $stmt = $pdo->prepare("
            SELECT user_id, username, display_name 
            FROM users 
            WHERE user_id = ? AND status != 'deleted'
        ");
        $stmt->execute([$other_user_id]);
        $other_user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$other_user) {
            return [
                'success' => false,
                'error' => 'User not found'
            ];
        }
        
        // Build query
        $where_clause = "
            ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
            AND deleted_at IS NULL
        ";
        $params = [$user_id, $other_user_id, $other_user_id, $user_id];
        
        // Add before_message_id condition for pagination
        if ($before_message_id) {
            $stmt = $pdo->prepare("SELECT created_at FROM messages WHERE message_id = ?");
            $stmt->execute([$before_message_id]);
            $before_timestamp = $stmt->fetchColumn();
            
            if ($before_timestamp) {
                $where_clause .= " AND created_at < ?";
                $params[] = $before_timestamp;
            }
        }
        
        // Get messages
        $stmt = $pdo->prepare("
            SELECT 
                m.message_id, m.sender_id, m.receiver_id, m.content, 
                m.message_type, m.encryption_key, m.file_id, m.created_at,
                m.read_at, m.delivered_at,
                u.username as sender_username, u.display_name as sender_display_name,
                f.original_filename, f.file_size, f.mime_type
            FROM messages m
            JOIN users u ON m.sender_id = u.user_id
            LEFT JOIN file_uploads f ON m.file_id = f.file_id
            WHERE {$where_clause}
            ORDER BY m.created_at DESC
            LIMIT ? OFFSET ?
        ");
        $params[] = $limit;
        $params[] = $offset;
        $stmt->execute($params);
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Mark messages as delivered if they haven't been marked yet
        if (!empty($messages)) {
            $message_ids = array_filter(array_map(function($msg) use ($user_id) {
                return ($msg['receiver_id'] === $user_id && !$msg['delivered_at']) ? $msg['message_id'] : null;
            }, $messages));
            
            if (!empty($message_ids)) {
                $placeholders = str_repeat('?,', count($message_ids) - 1) . '?';
                $stmt = $pdo->prepare("
                    UPDATE messages 
                    SET delivered_at = NOW()
                    WHERE message_id IN ({$placeholders})
                ");
                $stmt->execute($message_ids);
            }
        }
        
        // Get total count
        $count_params = [$user_id, $other_user_id, $other_user_id, $user_id];
        $stmt = $pdo->prepare("
            SELECT COUNT(*) 
            FROM messages 
            WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
                AND deleted_at IS NULL
        ");
        $stmt->execute($count_params);
        $total_count = $stmt->fetchColumn();
        
        return [
            'success' => true,
            'messages' => array_reverse($messages), // Reverse to show oldest first
            'other_user' => $other_user,
            'pagination' => [
                'total' => (int)$total_count,
                'limit' => $limit,
                'offset' => $offset,
                'has_more' => ($offset + $limit) < $total_count
            ]
        ];
        
    } catch (PDOException $e) {
        error_log("Get messages error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to retrieve messages'
        ];
    }
}

/**
 * Mark messages as read
 */
function markMessagesRead($pdo, $user_id, $data) {
    try {
        $message_ids = $data['message_ids'] ?? [];
        $other_user_id = $data['other_user_id'] ?? '';
        
        if (empty($message_ids) && empty($other_user_id)) {
            return [
                'success' => false,
                'error' => 'Either message_ids or other_user_id must be provided'
            ];
        }
        
        if (!empty($message_ids)) {
            // Mark specific messages as read
            if (!is_array($message_ids)) {
                $message_ids = [$message_ids];
            }
            
            $placeholders = str_repeat('?,', count($message_ids) - 1) . '?';
            $params = array_merge($message_ids, [$user_id]);
            
            $stmt = $pdo->prepare("
                UPDATE messages 
                SET read_at = NOW()
                WHERE message_id IN ({$placeholders})
                    AND receiver_id = ? 
                    AND read_at IS NULL
            ");
        } else {
            // Mark all messages from specific user as read
            $stmt = $pdo->prepare("
                UPDATE messages 
                SET read_at = NOW()
                WHERE sender_id = ? 
                    AND receiver_id = ? 
                    AND read_at IS NULL
            ");
            $params = [$other_user_id, $user_id];
        }
        
        $affected_rows = 0;
        if ($stmt->execute($params)) {
            $affected_rows = $stmt->rowCount();
        }
        
        return [
            'success' => true,
            'message' => 'Messages marked as read',
            'messages_updated' => $affected_rows
        ];
        
    } catch (PDOException $e) {
        error_log("Mark messages read error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to mark messages as read'
        ];
    }
}

/**
 * Delete message
 */
function deleteMessage($pdo, $user_id, $message_id) {
    try {
        // Check if user owns the message or is the receiver
        $stmt = $pdo->prepare("
            SELECT sender_id, receiver_id, deleted_at
            FROM messages 
            WHERE message_id = ?
        ");
        $stmt->execute([$message_id]);
        $message = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$message) {
            return [
                'success' => false,
                'error' => 'Message not found'
            ];
        }
        
        if ($message['deleted_at']) {
            return [
                'success' => false,
                'error' => 'Message already deleted'
            ];
        }
        
        // Only sender can delete message
        if ($message['sender_id'] !== $user_id) {
            return [
                'success' => false,
                'error' => 'You can only delete messages you sent'
            ];
        }
        
        // Soft delete the message
        $stmt = $pdo->prepare("
            UPDATE messages 
            SET deleted_at = NOW()
            WHERE message_id = ?
        ");
        
        if ($stmt->execute([$message_id])) {
            return [
                'success' => true,
                'message' => 'Message deleted successfully'
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Failed to delete message'
            ];
        }
        
    } catch (PDOException $e) {
        error_log("Delete message error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to delete message'
        ];
    }
}

/**
 * Get conversation list
 */
function getConversations($pdo, $user_id, $limit = 20, $offset = 0) {
    try {
        $limit = min(max(1, (int)$limit), 50); // Max 50 conversations
        $offset = max(0, (int)$offset);
        
        $stmt = $pdo->prepare("
            SELECT 
                CASE 
                    WHEN m.sender_id = ? THEN m.receiver_id 
                    ELSE m.sender_id 
                END as other_user_id,
                u.username as other_username,
                u.display_name as other_display_name,
                u.status as other_user_status,
                u.last_active as other_last_active,
                m.content as last_message_content,
                m.message_type as last_message_type,
                m.created_at as last_message_time,
                m.sender_id = ? as is_last_message_from_me,
                m.read_at as last_message_read_at,
                COUNT(CASE WHEN m2.receiver_id = ? AND m2.read_at IS NULL THEN 1 END) as unread_count
            FROM messages m
            JOIN users u ON (
                CASE 
                    WHEN m.sender_id = ? THEN m.receiver_id = u.user_id
                    ELSE m.sender_id = u.user_id
                END
            )
            LEFT JOIN messages m2 ON (
                (m2.sender_id = u.user_id AND m2.receiver_id = ?) OR
                (m2.sender_id = ? AND m2.receiver_id = u.user_id)
            ) AND m2.deleted_at IS NULL
            WHERE (m.sender_id = ? OR m.receiver_id = ?) 
                AND m.deleted_at IS NULL
                AND u.status != 'deleted'
                AND m.created_at = (
                    SELECT MAX(m3.created_at)
                    FROM messages m3
                    WHERE ((m3.sender_id = ? AND m3.receiver_id = u.user_id) OR 
                           (m3.sender_id = u.user_id AND m3.receiver_id = ?))
                        AND m3.deleted_at IS NULL
                )
            GROUP BY other_user_id, u.username, u.display_name, u.status, u.last_active,
                     m.content, m.message_type, m.created_at, m.sender_id, m.read_at
            ORDER BY m.created_at DESC
            LIMIT ? OFFSET ?
        ");
        
        $stmt->execute([
            $user_id, $user_id, $user_id, $user_id, $user_id, 
            $user_id, $user_id, $user_id, $user_id, $user_id, 
            $limit, $offset
        ]);
        $conversations = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get total count
        $stmt = $pdo->prepare("
            SELECT COUNT(DISTINCT 
                CASE 
                    WHEN m.sender_id = ? THEN m.receiver_id 
                    ELSE m.sender_id 
                END
            )
            FROM messages m
            JOIN users u ON (
                CASE 
                    WHEN m.sender_id = ? THEN m.receiver_id = u.user_id
                    ELSE m.sender_id = u.user_id
                END
            )
            WHERE (m.sender_id = ? OR m.receiver_id = ?) 
                AND m.deleted_at IS NULL
                AND u.status != 'deleted'
        ");
        $stmt->execute([$user_id, $user_id, $user_id, $user_id]);
        $total_count = $stmt->fetchColumn();
        
        return [
            'success' => true,
            'conversations' => $conversations,
            'pagination' => [
                'total' => (int)$total_count,
                'limit' => $limit,
                'offset' => $offset,
                'has_more' => ($offset + $limit) < $total_count
            ]
        ];
        
    } catch (PDOException $e) {
        error_log("Get conversations error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to retrieve conversations'
        ];
    }
}

/**
 * Get message statistics
 */
function getMessageStats($pdo, $user_id) {
    try {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_messages,
                COUNT(CASE WHEN sender_id = ? THEN 1 END) as sent_messages,
                COUNT(CASE WHEN receiver_id = ? THEN 1 END) as received_messages,
                COUNT(CASE WHEN receiver_id = ? AND read_at IS NULL THEN 1 END) as unread_messages,
                COUNT(CASE WHEN message_type = 'file' OR message_type = 'image' THEN 1 END) as file_messages,
                COUNT(DISTINCT CASE WHEN sender_id = ? THEN receiver_id WHEN receiver_id = ? THEN sender_id END) as conversation_count,
                MAX(created_at) as last_message_time
            FROM messages
            WHERE (sender_id = ? OR receiver_id = ?) AND deleted_at IS NULL
        ");
        $stmt->execute([$user_id, $user_id, $user_id, $user_id, $user_id, $user_id, $user_id]);
        $stats = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return [
            'success' => true,
            'statistics' => $stats
        ];
        
    } catch (PDOException $e) {
        error_log("Get message stats error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to retrieve message statistics'
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
    $input = json_decode(file_get_contents('php://input'), true);
    
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
    
    $action = $_GET['action'] ?? $input['action'] ?? '';
    $user_id = $current_user['user_id'];
    
    switch ($request_method) {
        case 'GET':
            switch ($action) {
                case 'conversation':
                    $other_user_id = $_GET['user_id'] ?? '';
                    $limit = $_GET['limit'] ?? 50;
                    $offset = $_GET['offset'] ?? 0;
                    $before_message_id = $_GET['before'] ?? null;
                    
                    if (empty($other_user_id)) {
                        $response = [
                            'success' => false,
                            'error' => 'User ID is required'
                        ];
                    } else {
                        $response = getMessages($pdo, $user_id, $other_user_id, $limit, $offset, $before_message_id);
                    }
                    break;
                    
                case 'conversations':
                    $limit = $_GET['limit'] ?? 20;
                    $offset = $_GET['offset'] ?? 0;
                    $response = getConversations($pdo, $user_id, $limit, $offset);
                    break;
                    
                case 'stats':
                    $response = getMessageStats($pdo, $user_id);
                    break;
                    
                default:
                    $response = [
                        'success' => false,
                        'error' => 'Invalid action for GET request'
                    ];
                    break;
            }
            break;
            
        case 'POST':
            switch ($action) {
                case 'send':
                    $response = sendMessage($pdo, $user_id, $input);
                    break;
                    
                case 'read':
                    $response = markMessagesRead($pdo, $user_id, $input);
                    break;
                    
                default:
                    $response = [
                        'success' => false,
                        'error' => 'Invalid action for POST request'
                    ];
                    break;
            }
            break;
            
        case 'DELETE':
            $message_id = $_GET['message_id'] ?? $input['message_id'] ?? '';
            if (empty($message_id)) {
                $response = [
                    'success' => false,
                    'error' => 'Message ID is required'
                ];
            } else {
                $response = deleteMessage($pdo, $user_id, $message_id);
            }
            break;
            
        default:
            $response = [
                'success' => false,
                'error' => 'Unsupported request method'
            ];
            break;
    }
    
    // Set appropriate HTTP status code
    if (!$response['success']) {
        if (strpos($response['error'], 'Authentication') !== false) {
            http_response_code(401);
        } elseif (strpos($response['error'], 'not found') !== false) {
            http_response_code(404);
        } else {
            http_response_code(400);
        }
    } else {
        http_response_code(200);
    }
    
    echo json_encode($response, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    error_log("Messages API error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error'
    ]);
}
?>
