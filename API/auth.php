<?php
require_once 'config.php';
require_once 'database.php';

header('Content-Type: application/json');
header("Access-Control-Allow-Origin: {$_ENV['CORS_ORIGIN']}");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key");
header("Access-Control-Max-Age: 3600");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Rate limiting check
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (!checkRateLimit($client_ip, 'auth', 10, 300)) { // 10 requests per 5 minutes
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'error' => 'Rate limit exceeded. Please try again later.',
        'retry_after' => 300
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
 * Enhanced login with persistent sessions
 */
function loginUser($pdo, $data) {
    try {
        // Validate required fields
        $required_fields = ['username', 'password'];
        foreach ($required_fields as $field) {
            if (empty($data[$field])) {
                return [
                    'success' => false,
                    'error' => "Missing required field: {$field}"
                ];
            }
        }

        $username = trim($data['username']);
        $password = trim($data['password']);
        $remember_me = isset($data['remember']) ? (bool)$data['remember'] : false;
        $device_info = $data['device_info'] ?? null;
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        // Get user by username or email
        $stmt = $pdo->prepare("
            SELECT user_id, username, email, password_hash, salt, status, 
                   display_name, failed_login_attempts, last_login_attempt
            FROM users 
            WHERE (username = ? OR email = ?) AND status IN ('active', 'verified')
        ");
        $stmt->execute([$username, $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return [
                'success' => false,
                'error' => 'Invalid username or password'
            ];
        }

        // Check for too many failed attempts
        if ($user['failed_login_attempts'] >= 5) {
            $last_attempt = new DateTime($user['last_login_attempt']);
            $now = new DateTime();
            $diff = $now->diff($last_attempt);
            
            if ($diff->h < 1) { // 1 hour lockout
                return [
                    'success' => false,
                    'error' => 'Account temporarily locked due to failed login attempts. Try again later.'
                ];
            }
        }

        // Verify password
        $hashed_input = hash('sha256', $password . $user['salt']);
        if (!hash_equals($user['password_hash'], $hashed_input)) {
            // Increment failed attempts
            $stmt = $pdo->prepare("
                UPDATE users 
                SET failed_login_attempts = failed_login_attempts + 1,
                    last_login_attempt = NOW()
                WHERE user_id = ?
            ");
            $stmt->execute([$user['user_id']]);
            
            return [
                'success' => false,
                'error' => 'Invalid username or password'
            ];
        }

        // Create new session
        $session_token = generateSessionToken();
        $expires_at = $remember_me ? 
            date('Y-m-d H:i:s', strtotime('+30 days')) : 
            date('Y-m-d H:i:s', strtotime('+24 hours'));

        // Deactivate old sessions for this user (optional - allow multiple sessions)
        $stmt = $pdo->prepare("
            UPDATE user_sessions 
            SET is_active = FALSE 
            WHERE user_id = ? AND remember_me = FALSE
        ");
        $stmt->execute([$user['user_id']]);

        // Insert new session
        $stmt = $pdo->prepare("
            INSERT INTO user_sessions (user_id, session_token, device_info, ip_address, remember_me, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $user['user_id'],
            $session_token,
            $device_info ? json_encode($device_info) : null,
            $ip_address,
            $remember_me,
            $expires_at
        ]);

        // Reset failed login attempts and update last login
        $stmt = $pdo->prepare("
            UPDATE users 
            SET failed_login_attempts = 0, 
                last_login = NOW(),
                last_login_attempt = NOW(),
                is_online = TRUE
            WHERE user_id = ?
        ");
        $stmt->execute([$user['user_id']]);

        // Update user presence
        $stmt = $pdo->prepare("
            INSERT INTO user_presence (user_id, status, device_info, ip_address)
            VALUES (?, 'online', ?, ?)
            ON DUPLICATE KEY UPDATE
                status = 'online',
                last_activity = NOW(),
                device_info = VALUES(device_info),
                ip_address = VALUES(ip_address)
        ");
        $stmt->execute([
            $user['user_id'],
            $device_info ? json_encode($device_info) : null,
            $ip_address
        ]);

        return [
            'success' => true,
            'data' => [
                'user_id' => $user['user_id'],
                'username' => $user['username'],
                'display_name' => $user['display_name'],
                'session_token' => $session_token,
                'expires_at' => $expires_at,
                'remember_me' => $remember_me
            ]
        ];

    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Login failed. Please try again.'
        ];
    }
}

/**
 * Register new user with enhanced validation
 */
function registerUser($pdo, $data) {
    try {
        // Validate required fields
        $required_fields = ['username', 'password', 'display_name'];
        foreach ($required_fields as $field) {
            if (empty($data[$field])) {
                return [
                    'success' => false,
                    'error' => "Missing required field: {$field}"
                ];
            }
        }
        
        $username = trim($data['username']);
        $password = $data['password'];
        $display_name = trim($data['display_name']);
        $email = isset($data['email']) ? trim($data['email']) : null;
        
        // Validate username
        if (strlen($username) < 3 || strlen($username) > 32) {
            return [
                'success' => false,
                'error' => 'Username must be between 3 and 32 characters'
            ];
        }
        
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
            return [
                'success' => false,
                'error' => 'Username can only contain letters, numbers, underscores, and hyphens'
            ];
        }
        
        // Validate password
        if (strlen($password) < 8) {
            return [
                'success' => false,
                'error' => 'Password must be at least 8 characters long'
            ];
        }
        
        // Check for existing username or email
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        if ($stmt->fetchColumn() > 0) {
            return [
                'success' => false,
                'error' => 'Username or email already exists'
            ];
        }
        
        // Generate password hash
        $salt = bin2hex(random_bytes(16));
        $password_hash = hash('sha256', $password . $salt);
        $user_id = bin2hex(random_bytes(16));
        
        // Insert user
        $stmt = $pdo->prepare("
            INSERT INTO users (user_id, username, password_hash, salt, display_name, email, created_at, status) 
            VALUES (?, ?, ?, ?, ?, ?, NOW(), 'active')
        ");
        
        if ($stmt->execute([$user_id, $username, $password_hash, $salt, $display_name, $email])) {
            // Auto-join global chat room
            $stmt = $pdo->prepare("
                INSERT INTO room_members (room_id, user_id, joined_at)
                SELECT room_id, ?, NOW() FROM chat_rooms WHERE name = 'global' LIMIT 1
            ");
            $stmt->execute([$user_id]);
            
            return [
                'success' => true,
                'message' => 'User registered successfully',
                'data' => [
                    'user_id' => $user_id,
                    'username' => $username,
                    'display_name' => $display_name
                ]
            ];
        } else {
            return [
                'success' => false,
                'error' => 'Failed to create user account'
            ];
        }
        
    } catch (PDOException $e) {
        error_log("Registration error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Registration failed. Please try again.'
        ];
    }
}

/**
 * Validate and refresh session
 */
function validateSession($pdo, $data) {
    try {
        $session_token = $data['session_token'] ?? '';
        
        if (empty($session_token)) {
            return [
                'success' => false,
                'error' => 'Session token required'
            ];
        }

        $stmt = $pdo->prepare("
            SELECT s.*, u.username, u.display_name, u.status
            FROM user_sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.session_token = ? AND s.is_active = TRUE AND s.expires_at > NOW()
        ");
        $stmt->execute([$session_token]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$session) {
            return [
                'success' => false,
                'error' => 'Invalid or expired session'
            ];
        }

        // Update last activity
        $stmt = $pdo->prepare("
            UPDATE user_sessions 
            SET last_activity = NOW() 
            WHERE session_token = ?
        ");
        $stmt->execute([$session_token]);

        // Update user presence
        $stmt = $pdo->prepare("
            UPDATE user_presence 
            SET last_activity = NOW() 
            WHERE user_id = ?
        ");
        $stmt->execute([$session['user_id']]);

        return [
            'success' => true,
            'data' => [
                'user_id' => $session['user_id'],
                'username' => $session['username'],
                'display_name' => $session['display_name'],
                'session_valid' => true
            ]
        ];

    } catch (Exception $e) {
        error_log("Session validation error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Session validation failed'
        ];
    }
}

/**
 * Logout user and invalidate session
 */
function logoutUser($pdo, $data) {
    try {
        $session_token = $data['session_token'] ?? '';
        
        if (empty($session_token)) {
            return [
                'success' => false,
                'error' => 'Session token required'
            ];
        }

        // Get user ID from session
        $stmt = $pdo->prepare("SELECT user_id FROM user_sessions WHERE session_token = ?");
        $stmt->execute([$session_token]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($session) {
            // Invalidate session
            $stmt = $pdo->prepare("UPDATE user_sessions SET is_active = FALSE WHERE session_token = ?");
            $stmt->execute([$session_token]);

            // Update user status
            $stmt = $pdo->prepare("UPDATE users SET is_online = FALSE WHERE user_id = ?");
            $stmt->execute([$session['user_id']]);

            // Update presence to offline
            $stmt = $pdo->prepare("
                UPDATE user_presence 
                SET status = 'offline', last_activity = NOW() 
                WHERE user_id = ?
            ");
            $stmt->execute([$session['user_id']]);
        }

        return [
            'success' => true,
            'message' => 'Logged out successfully'
        ];

    } catch (Exception $e) {
        error_log("Logout error: " . $e->getMessage());
        return [
            'success' => false,
            'error' => 'Logout failed'
        ];
    }
}

/**
 * Generate secure session token
 */
function generateSessionToken() {
    return bin2hex(random_bytes(32));
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
    
    if ($request_method === 'POST') {
        $action = $_GET['action'] ?? $input['action'] ?? '';
        
        switch ($action) {
            case 'register':
                $response = registerUser($pdo, $input);
                break;
                
            case 'login':
                $response = loginUser($pdo, $input);
                break;
                
            case 'logout':
                $session_data = ['session_token' => $_SERVER['HTTP_AUTHORIZATION'] ?? $input['session_token'] ?? ''];
                $session_data['session_token'] = str_replace('Bearer ', '', $session_data['session_token']);
                $response = logoutUser($pdo, $session_data);
                break;
                
            case 'verify':
            case 'validate':
                $session_data = ['session_token' => $_SERVER['HTTP_AUTHORIZATION'] ?? $input['session_token'] ?? ''];
                $session_data['session_token'] = str_replace('Bearer ', '', $session_data['session_token']);
                $response = validateSession($pdo, $session_data);
                break;
                
            default:
                $response = [
                    'success' => false,
                    'error' => 'Invalid action. Supported actions: register, login, logout, verify'
                ];
                break;
        }
    } else {
        $response = [
            'success' => false,
            'error' => 'Only POST requests are supported'
        ];
    }
    
    // Set appropriate HTTP status code
    if (!$response['success']) {
        if (strpos($response['error'], 'Rate limit') !== false) {
            http_response_code(429);
        } elseif (strpos($response['error'], 'Invalid') !== false || strpos($response['error'], 'expired') !== false) {
            http_response_code(401);
        } else {
            http_response_code(400);
        }
    } else {
        http_response_code(200);
    }
    
    echo json_encode($response);
    exit();
    
} catch (Exception $e) {
    error_log("Auth API error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error'
    ]);
    exit();
}
?>
