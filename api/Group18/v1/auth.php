<?php
/**
 * Authentication API
 * Endpoints: ?action=register, ?action=login, ?action=logout, ?action=send-otp, ?action=verify-otp
 */

// Enable error reporting for debugging
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);

try {
    require_once 'config.php';
} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Configuration error: ' . $e->getMessage()]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

try {
    $action = $_GET['action'] ?? $_POST['action'] ?? '';
    $method = $_SERVER['REQUEST_METHOD'];

    switch ($action) {
        case 'register':
            $method === 'POST' ? handleRegister() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
            break;
        case 'login':
            $method === 'POST' ? handleLogin() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
            break;
        case 'logout':
            $method === 'POST' ? handleLogout() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
            break;
        case 'send-otp':
            $method === 'POST' ? handleSendOTP() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
            break;
        case 'send-pre-register-otp':
            $method === 'POST' ? handleSendPreRegisterOTP() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
            break;
        case 'verify-pre-register-otp':
            $method === 'POST' ? handleVerifyPreRegisterOTP() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
            break;
        case 'verify-otp':
            $method === 'POST' ? handleVerifyOTP() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
            break;
        default:
            sendJSON(['success' => false, 'error' => 'Endpoint not found. Use ?action=register|login|logout|send-otp|verify-otp'], 404);
    }
} catch (Exception $e) {
    sendJSON(['success' => false, 'error' => 'Server error: ' . $e->getMessage()], 500);
}

function handleRegister() {
    $data = getBody();
    $email = clean($data['email'] ?? '');
    $username = clean($data['username'] ?? '');
    $password = $data['password'] ?? '';
    
    if (!$email || !$username || !$password) {
        sendJSON(['success' => false, 'error' => 'Missing fields'], 400);
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        sendJSON(['success' => false, 'error' => 'Invalid email'], 400);
    }
    
    if (strlen($password) < 8) {
        sendJSON(['success' => false, 'error' => 'Password must be at least 8 characters'], 400);
    }
    
    $db = getDB();
    
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ? OR username = ?");
    $stmt->execute([$email, $username]);
    if ($stmt->fetch()) {
        sendJSON(['success' => false, 'error' => 'Email or username already exists'], 400);
    }
    
    $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => PASSWORD_HASH_COST]);
    
    // Insert user as verified (email was verified client-side before registration)
    $stmt = $db->prepare("INSERT INTO users (email, username, password_hash, is_verified, created_at) VALUES (?, ?, ?, 1, NOW())");
    $stmt->execute([$email, $username, $passwordHash]);
    
    $userId = $db->lastInsertId();
    
    sendJSON(['success' => true, 'user_id' => $userId, 'message' => 'Registration successful. You can now login.']);
}

function handleLogin() {
    $data = getBody();
    $username = clean($data['username'] ?? '');
    $password = $data['password'] ?? '';
    
    if (!$username || !$password) {
        sendJSON(['success' => false, 'error' => 'Missing fields'], 400);
    }
    
    $db = getDB();
    
    $stmt = $db->prepare("SELECT id, username, email, password_hash, is_verified, is_active FROM users WHERE username = ? OR email = ?");
    $stmt->execute([$username, $username]);
    $user = $stmt->fetch();
    
    if (!$user || !password_verify($password, $user['password_hash'])) {
        sendJSON(['success' => false, 'error' => 'Invalid credentials'], 401);
    }
    
    if (!$user['is_active']) {
        sendJSON(['success' => false, 'error' => 'Account disabled'], 403);
    }
    
    if (!$user['is_verified']) {
        sendJSON(['success' => false, 'error' => 'Email not verified'], 403);
    }
    
    $sessionToken = bin2hex(random_bytes(32));
    
    $stmt = $db->prepare("INSERT INTO sessions (user_id, session_token, expires_at, created_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR), NOW())");
    $stmt->execute([$user['id'], $sessionToken]);
    
    $token = createToken([
        'user_id' => $user['id'],
        'username' => $user['username'],
        'session_token' => $sessionToken
    ]);
    
    sendJSON([
        'success' => true,
        'token' => $token,
        'user' => [
            'id' => $user['id'],
            'username' => $user['username'],
            'email' => $user['email']
        ]
    ]);
}

function handleLogout() {
    $user = requireAuth();
    
    $db = getDB();
    $stmt = $db->prepare("DELETE FROM sessions WHERE session_token = ?");
    $stmt->execute([$user['session_token'] ?? '']);
    
    sendJSON(['success' => true, 'message' => 'Logged out successfully']);
}

function handleSendOTP() {
    $data = getBody();
    $email = clean($data['email'] ?? '');
    
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        sendJSON(['success' => false, 'error' => 'Invalid email'], 400);
    }
    
    $db = getDB();
    
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    
    if (!$user) {
        sendJSON(['success' => false, 'error' => 'Email not found'], 404);
    }
    
    $stmt = $db->prepare("UPDATE otp_verifications SET is_used = 1 WHERE user_id = ? AND purpose = 'email_verification' AND is_used = 0");
    $stmt->execute([$user['id']]);
    
    $otp = generateOTP();
    
    $stmt = $db->prepare("INSERT INTO otp_verifications (user_id, otp_code, purpose, expires_at, created_at) VALUES (?, ?, 'email_verification', DATE_ADD(NOW(), INTERVAL 10 MINUTE), NOW())");
    $stmt->execute([$user['id'], $otp]);
    
    sendOTP($email, $otp);
    
    sendJSON(['success' => true, 'message' => 'OTP sent to email']);
}

function handleVerifyOTP() {
    $data = getBody();
    $email = clean($data['email'] ?? '');
    $otp = clean($data['otp'] ?? '');
    
    if (!$email || !$otp) {
        sendJSON(['success' => false, 'error' => 'Missing fields'], 400);
    }
    
    $db = getDB();
    
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    
    if (!$user) {
        sendJSON(['success' => false, 'error' => 'Email not found'], 404);
    }
    
    $stmt = $db->prepare("SELECT id FROM otp_verifications WHERE user_id = ? AND otp_code = ? AND purpose = 'email_verification' AND is_used = 0 AND expires_at > NOW()");
    $stmt->execute([$user['id'], $otp]);
    $otpRecord = $stmt->fetch();
    
    if (!$otpRecord) {
        sendJSON(['success' => false, 'error' => 'Invalid or expired OTP'], 400);
    }
    
    $stmt = $db->prepare("UPDATE otp_verifications SET is_used = 1 WHERE id = ?");
    $stmt->execute([$otpRecord['id']]);
    
    $stmt = $db->prepare("UPDATE users SET is_verified = 1, verified_at = NOW() WHERE id = ?");
    $stmt->execute([$user['id']]);
    
    sendJSON(['success' => true, 'message' => 'Email verified successfully']);
}

// New: Send OTP before registration
function handleSendPreRegisterOTP() {
    $data = getBody();
    $email = clean($data['email'] ?? '');
    
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        sendJSON(['success' => false, 'error' => 'Invalid email format'], 400);
    }
    
    $db = getDB();
    
    // Check if email already exists
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        sendJSON(['success' => false, 'error' => 'Email already registered. Try logging in.'], 400);
    }
    
    // Generate OTP
    $otp = generateOTP();
    
    // Clean up old pre-registration OTPs for this email
    $stmt = $db->prepare("DELETE FROM otp_verifications WHERE user_id = 0 AND purpose = ? AND created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)");
    $stmt->execute(['pre_reg_' . $email]);
    
    // Store OTP with email encoded in purpose field
    $stmt = $db->prepare("INSERT INTO otp_verifications (user_id, otp_code, purpose, expires_at, created_at) 
                          VALUES (0, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE), NOW())");
    $stmt->execute([$otp, 'pre_reg_' . $email]);
    
    // Try to send OTP
    $emailSent = sendOTP($email, $otp);
    
    if (!$emailSent) {
        sendJSON(['success' => false, 'error' => 'Failed to send email. Please check your email address or try again later.'], 500);
    }
    
    sendJSON(['success' => true, 'message' => 'OTP sent to email']);
}

// New: Verify pre-registration OTP
function handleVerifyPreRegisterOTP() {
    $data = getBody();
    $email = clean($data['email'] ?? '');
    $otp = clean($data['otp'] ?? '');
    
    if (!$email || !$otp) {
        sendJSON(['success' => false, 'error' => 'Missing fields'], 400);
    }
    
    $db = getDB();
    
    $stmt = $db->prepare("SELECT id FROM otp_verifications 
                          WHERE user_id = 0 AND otp_code = ? 
                          AND purpose = ? AND expires_at > NOW()");
    $stmt->execute([$otp, 'pre_reg_' . $email]);
    $otpRecord = $stmt->fetch();
    
    if (!$otpRecord) {
        sendJSON(['success' => false, 'error' => 'Invalid or expired OTP'], 400);
    }
    
    // Mark OTP as used
    $stmt = $db->prepare("DELETE FROM otp_verifications WHERE id = ?");
    $stmt->execute([$otpRecord['id']]);
    
    sendJSON(['success' => true, 'message' => 'Email verified successfully', 'verified_email' => $email]);
}
