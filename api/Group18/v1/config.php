<?php
/**
 * Database Configuration for Tornado Messenger
 * Hostinger MySQL Database
 */

// Database Configuration
define('DB_HOST', 'tk6ejd.h.filess.io');
define('DB_PORT', 61031);
define('DB_NAME', 'tornado_ableworemy');
define('DB_USER', 'tornado_ableworemy');
define('DB_PASS', 'a10b796574e5640e9abfdf12b73b7f332b941af7'); // UPDATE THIS WITH ACTUAL PASSWORD

// API Configuration
define('API_VERSION', 'v1');
define('JWT_SECRET', 'tornado_secret_key_change_me');
define('TOKEN_EXPIRY', 86400); // 24 hours
define('OTP_EXPIRY', 600); // 10 minutes
define('PASSWORD_HASH_COST', 12);

// File Upload Configuration
define('MAX_FILE_SIZE', 104857600); // 100MB
define('UPLOAD_DIR', __DIR__ . '/../../uploads');
define('ALLOWED_TYPES', ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip']);

// Email Configuration (for OTP)
define('SENDMAIL_URL', 'https://thegroup11.com/api/sendmail.php');
define('SENDMAIL_API_KEY', 'dGhlZ3JvdXAxMQ==');

/**
 * Get PDO database connection
 */
function getDB() {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=utf8mb4";
            $pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            die(json_encode(['success' => false, 'error' => 'Database connection failed']));
        }
    }
    return $pdo;
}

/**
 * Send JSON response
 */
function sendJSON($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    echo json_encode($data);
    exit;
}

/**
 * Get request body
 */
function getBody() {
    return json_decode(file_get_contents('php://input'), true) ?? [];
}

/**
 * Get Bearer token
 */
function getToken() {
    $headers = getallheaders();
    if (isset($headers['Authorization'])) {
        if (preg_match('/Bearer\s+(.+)/', $headers['Authorization'], $matches)) {
            return $matches[1];
        }
    }
    return null;
}

/**
 * Verify JWT token
 */
function verifyToken($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    
    [$header, $payload, $signature] = $parts;
    $validSig = hash_hmac('sha256', "$header.$payload", JWT_SECRET, true);
    $validSig = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($validSig));
    
    if ($signature !== $validSig) return null;
    
    $data = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $payload)), true);
    if (isset($data['exp']) && $data['exp'] < time()) return null;
    
    return $data;
}

/**
 * Create JWT token
 */
function createToken($payload) {
    $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $header = str_replace(['+', '/', '='], ['-', '_', ''], $header);
    
    $payload['iat'] = time();
    $payload['exp'] = time() + TOKEN_EXPIRY;
    $payload = base64_encode(json_encode($payload));
    $payload = str_replace(['+', '/', '='], ['-', '_', ''], $payload);
    
    $signature = hash_hmac('sha256', "$header.$payload", JWT_SECRET, true);
    $signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    return "$header.$payload.$signature";
}

/**
 * Require authentication
 */
function requireAuth() {
    $token = getToken();
    if (!$token) {
        sendJSON(['success' => false, 'error' => 'No token provided'], 401);
    }
    
    $user = verifyToken($token);
    if (!$user) {
        sendJSON(['success' => false, 'error' => 'Invalid token'], 401);
    }
    
    return $user;
}

/**
 * Send OTP email using GET method with query parameters
 */
function sendOTP($email, $otp) {
    // Build GET URL with query parameters
    $params = http_build_query([
        'api_key' => SENDMAIL_API_KEY,
        'to' => $email,
        'subject' => 'Tornado Messenger - Verification Code',
        'message' => "Your OTP code is: $otp\n\nThis code expires in 10 minutes.\n\nIf you didn't request this code, please ignore this email."
    ]);
    
    $url = SENDMAIL_URL . '?' . $params;
    
    // Try curl first
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        if ($ch === false) {
            error_log("OTP Send Failed - curl_init failed");
            return sendOTPFallback($url);
        }
        
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPGET => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_FOLLOWLOCATION => true
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        // Check HTTP status
        if ($httpCode !== 200) {
            error_log("OTP Send Failed - HTTP $httpCode: $error - Response: $response");
            return false;
        }
        
        // Parse JSON response
        $result = @json_decode($response, true);
        
        // Check if response indicates success
        if ($result && isset($result['success'])) {
            $success = $result['success'];
            return ($success === true || $success === 'Email sent successfully' || strpos($success, 'success') !== false);
        }
        
        error_log("OTP Send - Unexpected response: $response");
        return false;
    }
    
    // Fallback to file_get_contents
    return sendOTPFallback($url);
}

/**
 * Fallback email sending using file_get_contents
 */
function sendOTPFallback($url) {
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 30,
            'ignore_errors' => true
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    
    if ($response === false) {
        error_log("OTP Send Failed - file_get_contents failed");
        return false;
    }
    
    $result = @json_decode($response, true);
    
    if ($result && isset($result['success'])) {
        $success = $result['success'];
        return ($success === true || $success === 'Email sent successfully' || strpos($success, 'success') !== false);
    }
    
    error_log("OTP Send Fallback - Unexpected response: $response");
    return false;
}

/**
 * Generate OTP
 */
function generateOTP() {
    return str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
}

/**
 * Sanitize input
 */
function clean($str) {
    return htmlspecialchars(strip_tags(trim($str)), ENT_QUOTES, 'UTF-8');
}