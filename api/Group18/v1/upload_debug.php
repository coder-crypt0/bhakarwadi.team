<?php
/**
 * DEBUG VERSION - File Upload API with detailed error logging
 */

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('log_errors', '1');

require_once 'config.php';

// Log all incoming data for debugging
error_log("=== UPLOAD DEBUG START ===");
error_log("REQUEST_METHOD: " . $_SERVER['REQUEST_METHOD']);
error_log("Content-Type: " . ($_SERVER['CONTENT_TYPE'] ?? 'not set'));
error_log("POST data keys: " . implode(', ', array_keys($_POST)));
error_log("FILES data keys: " . implode(', ', array_keys($_FILES)));

if (isset($_POST['encrypted_content'])) {
    error_log("encrypted_content length: " . strlen($_POST['encrypted_content']));
}
if (isset($_POST['is_encrypted'])) {
    error_log("is_encrypted value: " . $_POST['is_encrypted']);
}
if (isset($_FILES['file'])) {
    error_log("file name: " . $_FILES['file']['name']);
    error_log("file size: " . $_FILES['file']['size']);
    error_log("file error: " . $_FILES['file']['error']);
    error_log("file tmp_name: " . $_FILES['file']['tmp_name']);
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

error_log("Action: $action, Method: $method");

if ($action !== 'upload' || $method !== 'POST') {
    sendJSON(['success' => false, 'error' => 'Invalid action or method'], 405);
}

try {
    error_log("Starting handleUpload...");
    
    $user = requireAuth();
    error_log("Auth successful, user_id: " . $user['user_id']);
    
    if (!isset($_FILES['file'])) {
        error_log("ERROR: No file uploaded in \$_FILES");
        sendJSON(['success' => false, 'error' => 'No file uploaded'], 400);
    }
    
    $file = $_FILES['file'];
    error_log("File received: " . print_r($file, true));
    
    $originalName = clean($file['name']);
    $fileSize = intval($file['size']);
    $tmpPath = $file['tmp_name'];
    
    error_log("Processing file: $originalName, size: $fileSize, tmp: $tmpPath");
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        error_log("ERROR: Upload error code: " . $file['error']);
        sendJSON(['success' => false, 'error' => 'Upload failed: ' . $file['error']], 400);
    }
    
    if ($fileSize > MAX_FILE_SIZE) {
        error_log("ERROR: File too large: $fileSize");
        sendJSON(['success' => false, 'error' => 'File too large (max 100MB)'], 400);
    }
    
    $encryptedContent = isset($_POST['encrypted_content']) ? $_POST['encrypted_content'] : null;
    $isEncrypted = isset($_POST['is_encrypted']) ? intval($_POST['is_encrypted']) : 0;
    
    error_log("isEncrypted: $isEncrypted, has encrypted_content: " . ($encryptedContent ? 'yes' : 'no'));
    
    if ($isEncrypted && !$encryptedContent) {
        error_log("ERROR: Missing encrypted_content");
        sendJSON(['success' => false, 'error' => 'Missing encrypted_content'], 400);
    }
    
    // For encrypted files, use the encrypted content size
    $actualFileData = null;
    if ($isEncrypted) {
        error_log("Decoding base64 encrypted content...");
        $actualFileData = base64_decode($encryptedContent);
        if ($actualFileData === false) {
            error_log("ERROR: Invalid base64 encoding");
            sendJSON(['success' => false, 'error' => 'Invalid base64 encoding'], 400);
        }
        $fileSize = strlen($actualFileData);
        error_log("Decoded encrypted data size: $fileSize");
        if ($fileSize > MAX_FILE_SIZE) {
            error_log("ERROR: Encrypted file too large: $fileSize");
            sendJSON(['success' => false, 'error' => 'File too large (max 100MB)'], 400);
        }
    }
    
    $uploadDir = UPLOAD_DIR . '/' . date('Y/m/d');
    error_log("Upload directory: $uploadDir");
    
    if (!file_exists($uploadDir)) {
        error_log("Creating directory: $uploadDir");
        if (!mkdir($uploadDir, 0755, true)) {
            error_log("ERROR: Failed to create upload directory");
            sendJSON(['success' => false, 'error' => 'Failed to create upload directory'], 500);
        }
    }
    
    if (!is_writable($uploadDir)) {
        error_log("ERROR: Upload directory not writable");
        sendJSON(['success' => false, 'error' => 'Upload directory not writable'], 500);
    }
    
    // For encrypted files, hash the encrypted content; for normal files, hash the uploaded file
    if ($isEncrypted) {
        error_log("Hashing encrypted data...");
        $fileHash = hash('sha256', $actualFileData);
    } else {
        error_log("Hashing uploaded file...");
        $fileHash = hash_file('sha256', $tmpPath);
    }
    error_log("File hash: $fileHash");
    
    $extension = pathinfo($originalName, PATHINFO_EXTENSION);
    $storedName = $fileHash . ($extension ? '.' . $extension : '');
    $storedPath = $uploadDir . '/' . $storedName;
    
    error_log("Storing file at: $storedPath");
    
    if ($isEncrypted) {
        error_log("Writing encrypted data to file...");
        if (file_put_contents($storedPath, $actualFileData) === false) {
            error_log("ERROR: Failed to write file");
            sendJSON(['success' => false, 'error' => 'Failed to write file'], 500);
        }
    } else {
        error_log("Moving uploaded file...");
        if (!move_uploaded_file($tmpPath, $storedPath)) {
            error_log("ERROR: Failed to save file");
            sendJSON(['success' => false, 'error' => 'Failed to save file'], 500);
        }
    }
    
    error_log("File saved successfully, inserting into database...");
    
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO files (user_id, filename, file_path, file_size, mime_type, upload_time) VALUES (?, ?, ?, ?, ?, NOW())");
    $stmt->execute([$user['user_id'], $originalName, $storedPath, $fileSize, $file['type']]);
    $fileId = $db->lastInsertId();
    
    error_log("Database insert successful, file_id: $fileId");
    error_log("=== UPLOAD DEBUG END (SUCCESS) ===");
    
    sendJSON(['success' => true, 'file_id' => $fileId, 'file_hash' => $fileHash]);
    
} catch (Exception $e) {
    error_log("=== EXCEPTION CAUGHT ===");
    error_log("Exception: " . $e->getMessage());
    error_log("File: " . $e->getFile());
    error_log("Line: " . $e->getLine());
    error_log("Trace: " . $e->getTraceAsString());
    error_log("=== UPLOAD DEBUG END (ERROR) ===");
    sendJSON(['success' => false, 'error' => 'Server error: ' . $e->getMessage()], 500);
}
