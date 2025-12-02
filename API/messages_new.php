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
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user) {
        // Update last activity
        $stmt = $pdo->prepare("UPDATE user_sessions SET last_activity = NOW() WHERE session_token = ?");
        $stmt->execute([$session_token]);
        
        $stmt = $pdo->prepare("UPDATE user_presence SET last_activity = NOW() WHERE user_id = ?");
        $stmt->execute([$user['user_id']]);
    }
    
    return $user;
}

/**
 * Send a private message between users
 */
function sendPrivateMessage($pdo, $sender_id, $data) {
    try {
        // Validate required fields
        if (empty($data['receiver_username']) || empty($data['content'])) {
            return [
                'success' => false,
                'error' => 'Receiver username and content are required'
            ];
        }
        
        $receiver_username = trim($data['receiver_username']);
        $content = trim($data['content']);
        $message_type = $data['message_type'] ?? 'text';
        
        // Get receiver user ID
        $stmt = $pdo->prepare("SELECT user_id FROM users WHERE username = ? AND status = 'active'");
        $stmt->execute([$receiver_username]);
        $receiver = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$receiver) {
            return [
                'success' => false,
                'error' => 'Receiver not found or inactive'
            ];
        }
        
        $receiver_id = $receiver['user_id'];
        
        // Check if sender is blocked by receiver
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM user_blocks 
            WHERE blocker_id = ? AND blocked_id = ? AND is_active = TRUE
        ");
        $stmt->execute([$receiver_id, $sender_id]);
        if ($stmt->fetchColumn() > 0) {
            return [
                'success' => false,
                'error' => 'Message blocked by receiver'
            ];
        }
        
        // Validate content length
        if (strlen($content) > 4000) {
            return [
                'success' => false,
                'error' => 'Message content too long (max 4000 characters)'
            ];
        }
        
        // Generate message ID
        $message_id = bin2hex(random_bytes(16));
        
        // Insert message
        $stmt = $pdo->prepare("
            INSERT INTO messages (message_id, sender_id, receiver_id, content, message_type, is_global, created_at)
            VALUES (?, ?, ?, ?, ?, FALSE, NOW())
        ");
        
        if ($stmt->execute([$message_id, $sender_id, $receiver_id, $content, $message_type])) {
            return [
                'success' => true,
                'message' => 'Private message sent successfully',
                'data' => [
                    'message_id' => $message_id,
                    'receiver_username' => $receiver_username,
                    'content' => $content,
                    'message_type' => $message_type,
                    'timestamp' => date('Y-m-d H:i:s')
                ]
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Failed to send message'
            ];
        }
        
    } catch (Exception $e) {
        error_log("Send private message error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to send message'
        ];
    }
}

/**
 * Send a message to global chat
 */
function sendGlobalMessage($pdo, $sender_id, $data) {
    try {
        // Validate required fields
        if (empty($data['content'])) {
            return [
                'success' => false,
                'error' => 'Content is required'
            ];
        }
        
        $content = trim($data['content']);
        $message_type = $data['message_type'] ?? 'text';
        
        // Validate content length
        if (strlen($content) > 4000) {
            return [
                'success' => false,
                'error' => 'Message content too long (max 4000 characters)'
            ];
        }
        
        // Get global chat room
        $stmt = $pdo->prepare("SELECT room_id FROM chat_rooms WHERE name = 'global' LIMIT 1");
        $stmt->execute();
        $room = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$room) {
            return [
                'success' => false,
                'error' => 'Global chat room not found'
            ];
        }
        
        $room_id = $room['room_id'];
        
        // Check if user is member of global room
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM room_members 
            WHERE room_id = ? AND user_id = ? AND is_active = TRUE
        ");
        $stmt->execute([$room_id, $sender_id]);
        if ($stmt->fetchColumn() == 0) {
            // Auto-join user to global chat
            $stmt = $pdo->prepare("
                INSERT INTO room_members (room_id, user_id, joined_at)
                VALUES (?, ?, NOW())
            ");
            $stmt->execute([$room_id, $sender_id]);
        }
        
        // Generate message ID
        $message_id = bin2hex(random_bytes(16));
        
        // Insert global message
        $stmt = $pdo->prepare("
            INSERT INTO messages (message_id, sender_id, room_id, content, message_type, is_global, created_at)
            VALUES (?, ?, ?, ?, ?, TRUE, NOW())
        ");
        
        if ($stmt->execute([$message_id, $sender_id, $room_id, $content, $message_type])) {
            return [
                'success' => true,
                'message' => 'Global message sent successfully',
                'data' => [
                    'message_id' => $message_id,
                    'content' => $content,
                    'message_type' => $message_type,
                    'timestamp' => date('Y-m-d H:i:s')
                ]
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Failed to send global message'
            ];
        }
        
    } catch (Exception $e) {
        error_log("Send global message error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to send global message'
        ];
    }
}

/**
 * Get private conversation history
 */
function getPrivateMessages($pdo, $user_id, $data) {
    try {
        if (empty($data['other_username'])) {
            return [
                'success' => false,
                'error' => 'Other username is required'
            ];
        }
        
        $other_username = trim($data['other_username']);
        $limit = min(100, intval($data['limit'] ?? 50));
        $offset = intval($data['offset'] ?? 0);
        
        // Get other user ID
        $stmt = $pdo->prepare("SELECT user_id FROM users WHERE username = ?");
        $stmt->execute([$other_username]);
        $other_user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$other_user) {
            return [
                'success' => false,
                'error' => 'User not found'
            ];
        }
        
        $other_user_id = $other_user['user_id'];
        
        // Get private messages between users
        $stmt = $pdo->prepare("
            SELECT m.message_id, m.content, m.message_type, m.created_at,
                   u.username as sender_username, u.display_name as sender_display_name
            FROM messages m
            JOIN users u ON m.sender_id = u.user_id
            WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
              AND m.is_global = FALSE
            ORDER BY m.created_at DESC
            LIMIT ? OFFSET ?
        ");
        $stmt->execute([$user_id, $other_user_id, $other_user_id, $user_id, $limit, $offset]);
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'success' => true,
            'data' => [
                'messages' => array_reverse($messages), // Reverse to show oldest first
                'other_username' => $other_username,
                'count' => count($messages)
            ]
        ];
        
    } catch (Exception $e) {
        error_log("Get private messages error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to retrieve messages'
        ];
    }
}

/**
 * Get global chat messages
 */
function getGlobalMessages($pdo, $user_id, $data) {
    try {
        $limit = min(100, intval($data['limit'] ?? 50));
        $offset = intval($data['offset'] ?? 0);
        
        // Get global chat room
        $stmt = $pdo->prepare("SELECT room_id FROM chat_rooms WHERE name = 'global' LIMIT 1");
        $stmt->execute();
        $room = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$room) {
            return [
                'success' => false,
                'error' => 'Global chat room not found'
            ];
        }
        
        // Get global messages excluding blocked users
        $stmt = $pdo->prepare("
            SELECT m.message_id, m.content, m.message_type, m.created_at,
                   u.username as sender_username, u.display_name as sender_display_name
            FROM messages m
            JOIN users u ON m.sender_id = u.user_id
            LEFT JOIN user_blocks b ON b.blocker_id = ? AND b.blocked_id = m.sender_id AND b.is_active = TRUE
            WHERE m.room_id = ? AND m.is_global = TRUE AND b.block_id IS NULL
            ORDER BY m.created_at DESC
            LIMIT ? OFFSET ?
        ");
        $stmt->execute([$user_id, $room['room_id'], $limit, $offset]);
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'success' => true,
            'data' => [
                'messages' => array_reverse($messages), // Reverse to show oldest first
                'count' => count($messages)
            ]
        ];
        
    } catch (Exception $e) {
        error_log("Get global messages error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to retrieve global messages'
        ];
    }
}

/**
 * Block a user
 */
function blockUser($pdo, $blocker_id, $data) {
    try {
        if (empty($data['blocked_username'])) {
            return [
                'success' => false,
                'error' => 'Username to block is required'
            ];
        }
        
        $blocked_username = trim($data['blocked_username']);
        $reason = trim($data['reason'] ?? '');
        
        // Get blocked user ID
        $stmt = $pdo->prepare("SELECT user_id FROM users WHERE username = ?");
        $stmt->execute([$blocked_username]);
        $blocked_user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$blocked_user) {
            return [
                'success' => false,
                'error' => 'User not found'
            ];
        }
        
        if ($blocked_user['user_id'] === $blocker_id) {
            return [
                'success' => false,
                'error' => 'Cannot block yourself'
            ];
        }
        
        // Check if already blocked
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM user_blocks 
            WHERE blocker_id = ? AND blocked_id = ? AND is_active = TRUE
        ");
        $stmt->execute([$blocker_id, $blocked_user['user_id']]);
        if ($stmt->fetchColumn() > 0) {
            return [
                'success' => false,
                'error' => 'User is already blocked'
            ];
        }
        
        // Insert block record
        $block_id = bin2hex(random_bytes(16));
        $stmt = $pdo->prepare("
            INSERT INTO user_blocks (block_id, blocker_id, blocked_id, reason, created_at)
            VALUES (?, ?, ?, ?, NOW())
        ");
        
        if ($stmt->execute([$block_id, $blocker_id, $blocked_user['user_id'], $reason])) {
            return [
                'success' => true,
                'message' => "User '{$blocked_username}' has been blocked"
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Failed to block user'
            ];
        }
        
    } catch (Exception $e) {
        error_log("Block user error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to block user'
        ];
    }
}

/**
 * Unblock a user
 */
function unblockUser($pdo, $blocker_id, $data) {
    try {
        if (empty($data['blocked_username'])) {
            return [
                'success' => false,
                'error' => 'Username to unblock is required'
            ];
        }
        
        $blocked_username = trim($data['blocked_username']);
        
        // Get blocked user ID
        $stmt = $pdo->prepare("SELECT user_id FROM users WHERE username = ?");
        $stmt->execute([$blocked_username]);
        $blocked_user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$blocked_user) {
            return [
                'success' => false,
                'error' => 'User not found'
            ];
        }
        
        // Update block to inactive
        $stmt = $pdo->prepare("
            UPDATE user_blocks 
            SET is_active = FALSE, updated_at = NOW()
            WHERE blocker_id = ? AND blocked_id = ? AND is_active = TRUE
        ");
        
        if ($stmt->execute([$blocker_id, $blocked_user['user_id']]) && $stmt->rowCount() > 0) {
            return [
                'success' => true,
                'message' => "User '{$blocked_username}' has been unblocked"
            ];
        } else {
            return [
                'success' => false,
                'error' => 'User was not blocked or already unblocked'
            ];
        }
        
    } catch (Exception $e) {
        error_log("Unblock user error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to unblock user'
        ];
    }
}

/**
 * Get online users list
 */
function getOnlineUsers($pdo, $user_id, $data) {
    try {
        $limit = min(100, intval($data['limit'] ?? 50));
        
        // Get online users excluding blocked ones
        $stmt = $pdo->prepare("
            SELECT u.username, u.display_name, p.status, p.last_activity
            FROM users u
            JOIN user_presence p ON u.user_id = p.user_id
            LEFT JOIN user_blocks b ON (b.blocker_id = ? AND b.blocked_id = u.user_id AND b.is_active = TRUE)
                                    OR (b.blocker_id = u.user_id AND b.blocked_id = ? AND b.is_active = TRUE)
            WHERE p.status IN ('online', 'away') 
              AND u.user_id != ?
              AND u.status = 'active'
              AND b.block_id IS NULL
            ORDER BY p.last_activity DESC
            LIMIT ?
        ");
        $stmt->execute([$user_id, $user_id, $user_id, $limit]);
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'success' => true,
            'data' => [
                'users' => $users,
                'count' => count($users)
            ]
        ];
        
    } catch (Exception $e) {
        error_log("Get online users error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to get online users'
        ];
    }
}

/**
 * Get blocked users list
 */
function getBlockedUsers($pdo, $user_id, $data) {
    try {
        $stmt = $pdo->prepare("
            SELECT u.username, u.display_name, b.reason, b.created_at
            FROM user_blocks b
            JOIN users u ON b.blocked_id = u.user_id
            WHERE b.blocker_id = ? AND b.is_active = TRUE
            ORDER BY b.created_at DESC
        ");
        $stmt->execute([$user_id]);
        $blocked_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'success' => true,
            'data' => [
                'blocked_users' => $blocked_users,
                'count' => count($blocked_users)
            ]
        ];
        
    } catch (Exception $e) {
        error_log("Get blocked users error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Failed to get blocked users'
        ];
    }
}

/**
 * Rate limiting function
 */
function checkRateLimit($client_ip, $action, $limit, $window) {
    $rate_limit_file = "/tmp/rate_limit_{$action}_{$client_ip}.txt";
    
    // Create data array if file doesn't exist
    if (!file_exists($rate_limit_file)) {
        $data = ['count' => 0, 'window_start' => time()];
    } else {
        $data = json_decode(file_get_contents($rate_limit_file), true);
        if (!$data) {
            $data = ['count' => 0, 'window_start' => time()];
        }
    }
    
    $current_time = time();
    
    // Reset window if expired
    if (($current_time - $data['window_start']) >= $window) {
        $data = ['count' => 1, 'window_start' => $current_time];
    } else {
        $data['count']++;
    }
    
    // Check if limit exceeded
    if ($data['count'] > $limit) {
        return false;
    }
    
    file_put_contents($rate_limit_file, json_encode($data));
    return true;
}

// Main request handler
try {
    $request_method = $_SERVER['REQUEST_METHOD'];
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Get session token
    $session_token = $_SERVER['HTTP_AUTHORIZATION'] ?? $input['session_token'] ?? '';
    $session_token = str_replace('Bearer ', '', $session_token);
    
    // Authenticate user
    $user = authenticateUser($pdo, $session_token);
    if (!$user) {
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'error' => 'Invalid or expired session token'
        ]);
        exit();
    }
    
    $user_id = $user['user_id'];
    $action = $_GET['action'] ?? $input['action'] ?? '';
    
    switch ($request_method) {
        case 'POST':
            switch ($action) {
                case 'send_private':
                    $response = sendPrivateMessage($pdo, $user_id, $input);
                    break;
                    
                case 'send_global':
                    $response = sendGlobalMessage($pdo, $user_id, $input);
                    break;
                    
                case 'block_user':
                    $response = blockUser($pdo, $user_id, $input);
                    break;
                    
                case 'unblock_user':
                    $response = unblockUser($pdo, $user_id, $input);
                    break;
                    
                default:
                    $response = [
                        'success' => false,
                        'error' => 'Invalid action for POST request'
                    ];
                    break;
            }
            break;
            
        case 'GET':
            switch ($action) {
                case 'private_messages':
                    $response = getPrivateMessages($pdo, $user_id, $_GET);
                    break;
                    
                case 'global_messages':
                    $response = getGlobalMessages($pdo, $user_id, $_GET);
                    break;
                    
                case 'online_users':
                    $response = getOnlineUsers($pdo, $user_id, $_GET);
                    break;
                    
                case 'blocked_users':
                    $response = getBlockedUsers($pdo, $user_id, $_GET);
                    break;
                    
                default:
                    $response = [
                        'success' => false,
                        'error' => 'Invalid action for GET request'
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
        if (strpos($response['error'], 'Rate limit') !== false) {
            http_response_code(429);
        } elseif (strpos($response['error'], 'not found') !== false) {
            http_response_code(404);
        } elseif (strpos($response['error'], 'blocked') !== false) {
            http_response_code(403);
        } else {
            http_response_code(400);
        }
    } else {
        http_response_code(200);
    }
    
    echo json_encode($response);
    
} catch (Exception $e) {
    error_log("Messages API error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error'
    ]);
}
?>
