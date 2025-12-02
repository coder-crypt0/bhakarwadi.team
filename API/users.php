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
if (!checkRateLimit($client_ip, 'users', 50, 300)) { // 50 requests per 5 minutes
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
 * Get user profile information
 */
function getUserProfile($pdo, $user_id, $target_user = null) {
    try {
        $target_id = $target_user ?? $user_id;
        
        $stmt = $pdo->prepare("
            SELECT user_id, username, display_name, email, status, 
                   created_at, last_active,
                   CASE WHEN user_id = ? THEN TRUE ELSE FALSE END as is_own_profile
            FROM users 
            WHERE user_id = ? AND status != 'deleted'
        ");
        $stmt->execute([$user_id, $target_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            return [
                'success' => false,
                'error' => 'User not found'
            ];
        }
        
        // Hide sensitive information for other users' profiles
        if (!$user['is_own_profile']) {
            unset($user['email']);
        }
        
        // Get user statistics
        $stmt = $pdo->prepare("
            SELECT 
                (SELECT COUNT(*) FROM messages WHERE sender_id = ? OR receiver_id = ?) as total_messages,
                (SELECT COUNT(*) FROM file_uploads WHERE user_id = ?) as total_files
        ");
        $stmt->execute([$target_id, $target_id, $target_id]);
        $stats = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $user['statistics'] = $stats;
        unset($user['is_own_profile']);
        
        return [
            'success' => true,
            'user' => $user
        ];
        
    } catch (PDOException $e) {
        error_log("Get user profile error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to retrieve user profile'
        ];
    }
}

/**
 * Update user profile
 */
function updateUserProfile($pdo, $user_id, $data) {
    try {
        $allowed_fields = ['display_name', 'email', 'status'];
        $updates = [];
        $values = [];
        
        foreach ($allowed_fields as $field) {
            if (isset($data[$field]) && $data[$field] !== '') {
                switch ($field) {
                    case 'display_name':
                        $display_name = trim($data[$field]);
                        if (strlen($display_name) < 1 || strlen($display_name) > 100) {
                            return [
                                'success' => false,
                                'error' => 'Display name must be between 1 and 100 characters'
                            ];
                        }
                        $updates[] = "display_name = ?";
                        $values[] = $display_name;
                        break;
                        
                    case 'email':
                        $email = trim($data[$field]);
                        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                            return [
                                'success' => false,
                                'error' => 'Invalid email address format'
                            ];
                        }
                        
                        // Check if email is already in use
                        $stmt = $pdo->prepare("SELECT user_id FROM users WHERE email = ? AND user_id != ?");
                        $stmt->execute([$email, $user_id]);
                        if ($stmt->fetchColumn()) {
                            return [
                                'success' => false,
                                'error' => 'Email address is already in use'
                            ];
                        }
                        
                        $updates[] = "email = ?";
                        $values[] = $email;
                        break;
                        
                    case 'status':
                        $status = $data[$field];
                        if (!in_array($status, ['active', 'away', 'busy', 'invisible'])) {
                            return [
                                'success' => false,
                                'error' => 'Invalid status. Allowed values: active, away, busy, invisible'
                            ];
                        }
                        $updates[] = "status = ?";
                        $values[] = $status;
                        break;
                }
            }
        }
        
        if (empty($updates)) {
            return [
                'success' => false,
                'error' => 'No valid fields to update'
            ];
        }
        
        $updates[] = "updated_at = NOW()";
        $values[] = $user_id;
        
        $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE user_id = ?";
        $stmt = $pdo->prepare($sql);
        
        if ($stmt->execute($values)) {
            return [
                'success' => true,
                'message' => 'Profile updated successfully'
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Failed to update profile'
            ];
        }
        
    } catch (PDOException $e) {
        error_log("Update user profile error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Database error occurred'
        ];
    }
}

/**
 * Change user password
 */
function changePassword($pdo, $user_id, $data) {
    try {
        // Validate required fields
        if (empty($data['current_password']) || empty($data['new_password'])) {
            return [
                'success' => false,
                'error' => 'Current password and new password are required'
            ];
        }
        
        $current_password = $data['current_password'];
        $new_password = $data['new_password'];
        
        // Get current password hash
        $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $hash = $stmt->fetchColumn();
        
        if (!$hash) {
            return [
                'success' => false,
                'error' => 'User not found'
            ];
        }
        
        // Verify current password
        if (!password_verify($current_password, $hash)) {
            return [
                'success' => false,
                'error' => 'Current password is incorrect'
            ];
        }
        
        // Validate new password
        if (strlen($new_password) < 8) {
            return [
                'success' => false,
                'error' => 'New password must be at least 8 characters long'
            ];
        }
        
        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/', $new_password)) {
            return [
                'success' => false,
                'error' => 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            ];
        }
        
        // Check if new password is different from current
        if (password_verify($new_password, $hash)) {
            return [
                'success' => false,
                'error' => 'New password must be different from current password'
            ];
        }
        
        // Hash new password
        $new_hash = password_hash($new_password, PASSWORD_BCRYPT, ['cost' => 12]);
        
        // Update password
        $stmt = $pdo->prepare("
            UPDATE users 
            SET password_hash = ?, updated_at = NOW()
            WHERE user_id = ?
        ");
        
        if ($stmt->execute([$new_hash, $user_id])) {
            // Invalidate all existing sessions except current one
            $current_session = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            $current_session = str_replace('Bearer ', '', $current_session);
            
            $stmt = $pdo->prepare("
                UPDATE user_sessions 
                SET is_active = FALSE, updated_at = NOW()
                WHERE user_id = ? AND session_token != ?
            ");
            $stmt->execute([$user_id, $current_session]);
            
            return [
                'success' => true,
                'message' => 'Password changed successfully. Other sessions have been invalidated.'
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Failed to update password'
            ];
        }
        
    } catch (PDOException $e) {
        error_log("Change password error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Password change failed'
        ];
    }
}

/**
 * Search for users
 */
function searchUsers($pdo, $query, $limit = 20, $offset = 0) {
    try {
        $search_term = '%' . trim($query) . '%';
        $limit = min(max(1, (int)$limit), 50); // Max 50 results
        $offset = max(0, (int)$offset);
        
        $stmt = $pdo->prepare("
            SELECT user_id, username, display_name, status, last_active
            FROM users 
            WHERE (username LIKE ? OR display_name LIKE ?) 
                AND status != 'deleted'
                AND status != 'invisible'
            ORDER BY 
                CASE WHEN username LIKE ? THEN 1 ELSE 2 END,
                last_active DESC
            LIMIT ? OFFSET ?
        ");
        $stmt->execute([$search_term, $search_term, $query . '%', $limit, $offset]);
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get total count
        $stmt = $pdo->prepare("
            SELECT COUNT(*) 
            FROM users 
            WHERE (username LIKE ? OR display_name LIKE ?) 
                AND status != 'deleted'
                AND status != 'invisible'
        ");
        $stmt->execute([$search_term, $search_term]);
        $total_count = $stmt->fetchColumn();
        
        return [
            'success' => true,
            'users' => $users,
            'pagination' => [
                'total' => (int)$total_count,
                'limit' => $limit,
                'offset' => $offset,
                'has_more' => ($offset + $limit) < $total_count
            ]
        ];
        
    } catch (PDOException $e) {
        error_log("Search users error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Search failed'
        ];
    }
}

/**
 * Get user's active sessions
 */
function getUserSessions($pdo, $user_id) {
    try {
        $stmt = $pdo->prepare("
            SELECT session_id, ip_address, user_agent, created_at, updated_at, expires_at
            FROM user_sessions 
            WHERE user_id = ? AND is_active = TRUE AND expires_at > NOW()
            ORDER BY updated_at DESC
        ");
        $stmt->execute([$user_id]);
        $sessions = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'success' => true,
            'sessions' => $sessions
        ];
        
    } catch (PDOException $e) {
        error_log("Get user sessions error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to retrieve sessions'
        ];
    }
}

/**
 * Delete user session
 */
function deleteUserSession($pdo, $user_id, $session_id) {
    try {
        $stmt = $pdo->prepare("
            UPDATE user_sessions 
            SET is_active = FALSE, updated_at = NOW()
            WHERE user_id = ? AND session_id = ? AND is_active = TRUE
        ");
        
        if ($stmt->execute([$user_id, $session_id]) && $stmt->rowCount() > 0) {
            return [
                'success' => true,
                'message' => 'Session deleted successfully'
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Session not found or already inactive'
            ];
        }
        
    } catch (PDOException $e) {
        error_log("Delete user session error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to delete session'
        ];
    }
}

/**
 * Delete user account
 */
function deleteUserAccount($pdo, $user_id, $password) {
    try {
        // Verify password before deletion
        $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $hash = $stmt->fetchColumn();
        
        if (!$hash || !password_verify($password, $hash)) {
            return [
                'success' => false,
                'error' => 'Invalid password'
            ];
        }
        
        // Start transaction
        $pdo->beginTransaction();
        
        try {
            // Mark user as deleted instead of actually deleting
            $stmt = $pdo->prepare("
                UPDATE users 
                SET status = 'deleted', 
                    email = CONCAT(email, '_deleted_', UNIX_TIMESTAMP()),
                    updated_at = NOW()
                WHERE user_id = ?
            ");
            $stmt->execute([$user_id]);
            
            // Deactivate all sessions
            $stmt = $pdo->prepare("
                UPDATE user_sessions 
                SET is_active = FALSE, updated_at = NOW()
                WHERE user_id = ?
            ");
            $stmt->execute([$user_id]);
            
            // Mark messages as deleted (keep for investigation purposes)
            $stmt = $pdo->prepare("
                UPDATE messages 
                SET deleted_at = NOW()
                WHERE sender_id = ? OR receiver_id = ?
            ");
            $stmt->execute([$user_id, $user_id]);
            
            $pdo->commit();
            
            return [
                'success' => true,
                'message' => 'Account deleted successfully'
            ];
            
        } catch (Exception $e) {
            $pdo->rollBack();
            throw $e;
        }
        
    } catch (PDOException $e) {
        error_log("Delete user account error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to delete account'
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
                case 'profile':
                    $target_user = $_GET['user_id'] ?? $user_id;
                    $response = getUserProfile($pdo, $user_id, $target_user);
                    break;
                    
                case 'search':
                    $query = $_GET['q'] ?? '';
                    $limit = $_GET['limit'] ?? 20;
                    $offset = $_GET['offset'] ?? 0;
                    
                    if (empty($query)) {
                        $response = [
                            'success' => false,
                            'error' => 'Search query is required'
                        ];
                    } else {
                        $response = searchUsers($pdo, $query, $limit, $offset);
                    }
                    break;
                    
                case 'sessions':
                    $response = getUserSessions($pdo, $user_id);
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
        case 'PUT':
            switch ($action) {
                case 'profile':
                    $response = updateUserProfile($pdo, $user_id, $input);
                    break;
                    
                case 'password':
                    $response = changePassword($pdo, $user_id, $input);
                    break;
                    
                default:
                    $response = [
                        'success' => false,
                        'error' => 'Invalid action for POST/PUT request'
                    ];
                    break;
            }
            break;
            
        case 'DELETE':
            switch ($action) {
                case 'session':
                    $session_id = $_GET['session_id'] ?? $input['session_id'] ?? '';
                    if (empty($session_id)) {
                        $response = [
                            'success' => false,
                            'error' => 'Session ID is required'
                        ];
                    } else {
                        $response = deleteUserSession($pdo, $user_id, $session_id);
                    }
                    break;
                    
                case 'account':
                    $password = $input['password'] ?? '';
                    if (empty($password)) {
                        $response = [
                            'success' => false,
                            'error' => 'Password is required to delete account'
                        ];
                    } else {
                        $response = deleteUserAccount($pdo, $user_id, $password);
                    }
                    break;
                    
                default:
                    $response = [
                        'success' => false,
                        'error' => 'Invalid action for DELETE request'
                    ];
                    break;
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
    error_log("Users API error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error'
    ]);
}
?>
