<?php
/**
 * File Upload/Download API
 * Endpoints: ?action=upload, ?action=download, ?action=info, ?action=delete, ?action=stream, ?action=view-once
 */

require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

switch ($action) {
    case 'upload':
        $method === 'POST' ? handleUpload() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'download':
        $method === 'GET' ? handleDownload() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'info':
        $method === 'GET' ? handleInfo() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'delete':
        $method === 'DELETE' ? handleFileDelete() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'stream':
        $method === 'GET' ? handleStream() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'view-once-upload':
        $method === 'POST' ? handleViewOnceUpload() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'view-once-download':
        $method === 'GET' ? handleViewOnceDownload() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    default:
        sendJSON(['success' => false, 'error' => 'Endpoint not found'], 404);
}

function handleUpload() {
    $user = requireAuth();
    
    if (!isset($_FILES['file'])) {
        sendJSON(['success' => false, 'error' => 'No file uploaded'], 400);
    }
    
    $file = $_FILES['file'];
    $originalName = clean($file['name']);
    $fileSize = intval($file['size']);
    $tmpPath = $file['tmp_name'];
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        sendJSON(['success' => false, 'error' => 'Upload failed: ' . $file['error']], 400);
    }
    
    if ($fileSize > MAX_FILE_SIZE) {
        sendJSON(['success' => false, 'error' => 'File too large (max 100MB)'], 400);
    }
    
    $encryptedContent = isset($_POST['encrypted_content']) ? $_POST['encrypted_content'] : null;
    $isEncrypted = isset($_POST['is_encrypted']) ? intval($_POST['is_encrypted']) : 0;
    
    if ($isEncrypted && !$encryptedContent) {
        sendJSON(['success' => false, 'error' => 'Missing encrypted_content'], 400);
    }
    
    // For encrypted files, use the encrypted content size
    $actualFileData = null;
    if ($isEncrypted) {
        $actualFileData = base64_decode($encryptedContent);
        if ($actualFileData === false) {
            sendJSON(['success' => false, 'error' => 'Invalid base64 encoding'], 400);
        }
        $fileSize = strlen($actualFileData);
        if ($fileSize > MAX_FILE_SIZE) {
            sendJSON(['success' => false, 'error' => 'File too large (max 100MB)'], 400);
        }
    }
    
    $uploadDir = UPLOAD_DIR . '/' . date('Y/m/d');
    if (!file_exists($uploadDir)) {
        if (!mkdir($uploadDir, 0755, true)) {
            sendJSON(['success' => false, 'error' => 'Failed to create upload directory'], 500);
        }
    }
    
    if (!is_writable($uploadDir)) {
        sendJSON(['success' => false, 'error' => 'Upload directory not writable'], 500);
    }
    
    // For encrypted files, hash the encrypted content; for normal files, hash the uploaded file
    if ($isEncrypted) {
        $fileHash = hash('sha256', $actualFileData);
    } else {
        $fileHash = hash_file('sha256', $tmpPath);
    }
    $extension = pathinfo($originalName, PATHINFO_EXTENSION);
    $storedName = $fileHash . ($extension ? '.' . $extension : '');
    $storedPath = $uploadDir . '/' . $storedName;
    
    if ($isEncrypted) {
        if (file_put_contents($storedPath, $actualFileData) === false) {
            sendJSON(['success' => false, 'error' => 'Failed to write file'], 500);
        }
    } else {
        if (!move_uploaded_file($tmpPath, $storedPath)) {
            sendJSON(['success' => false, 'error' => 'Failed to save file'], 500);
        }
    }
    
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO files (user_id, filename, file_path, file_size, mime_type, upload_time) VALUES (?, ?, ?, ?, ?, NOW())");
    $stmt->execute([$user['user_id'], $originalName, $storedPath, $fileSize, $file['type']]);
    $fileId = $db->lastInsertId();
    
    sendJSON(['success' => true, 'file_id' => $fileId, 'file_hash' => $fileHash]);
}

function handleDownload() {
    $user = requireAuth();
    $fileId = intval($_GET['file_id'] ?? 0);
    
    if (!$fileId) {
        sendJSON(['success' => false, 'error' => 'Missing file_id'], 400);
    }
    
    $db = getDB();
    $stmt = $db->prepare("SELECT f.*, u.username as owner FROM files f JOIN users u ON f.user_id = u.id WHERE f.id = ?");
    $stmt->execute([$fileId]);
    $file = $stmt->fetch();
    
    if (!$file) {
        sendJSON(['success' => false, 'error' => 'File not found'], 404);
    }
    
    // Check if user has access to the file
    // User has access if:
    // 1. User is the file owner (uploader)
    // 2. File was shared with user via a message (user is sender or receiver)
    $hasAccess = ($file['user_id'] == $user['user_id']);
    
    if (!$hasAccess) {
        // Check if file was shared via message
        $stmt = $db->prepare("
            SELECT COUNT(*) as count 
            FROM messages 
            WHERE file_id = ? 
            AND (sender_id = ? OR receiver_id = ?)
        ");
        $stmt->execute([$fileId, $user['user_id'], $user['user_id']]);
        $result = $stmt->fetch();
        
        if ($result && $result['count'] > 0) {
            $hasAccess = true;
        }
    }
    
    if (!$hasAccess) {
        sendJSON(['success' => false, 'error' => 'Access denied'], 403);
    }
    
    if (!file_exists($file['file_path'])) {
        sendJSON(['success' => false, 'error' => 'File missing on server'], 404);
    }
    
    header('Content-Type: ' . $file['mime_type']);
    header('Content-Length: ' . $file['file_size']);
    header('Content-Disposition: attachment; filename="' . $file['filename'] . '"');
    
    readfile($file['file_path']);
    exit;
}

function handleStream() {
    $user = requireAuth();
    $fileId = intval($_GET['file_id'] ?? 0);
    
    if (!$fileId) {
        sendJSON(['success' => false, 'error' => 'Missing file_id'], 400);
    }
    
    $db = getDB();
    $stmt = $db->prepare("SELECT f.*, u.username as owner FROM files f JOIN users u ON f.user_id = u.id WHERE f.id = ?");
    $stmt->execute([$fileId]);
    $file = $stmt->fetch();
    
    if (!$file) {
        sendJSON(['success' => false, 'error' => 'File not found'], 404);
    }
    
    // Check if user has access to the file
    // User has access if:
    // 1. User is the file owner (uploader)
    // 2. File was shared with user via a message (user is sender or receiver)
    $hasAccess = ($file['user_id'] == $user['user_id']);
    
    if (!$hasAccess) {
        // Check if file was shared via message
        $stmt = $db->prepare("
            SELECT COUNT(*) as count 
            FROM messages 
            WHERE file_id = ? 
            AND (sender_id = ? OR receiver_id = ?)
        ");
        $stmt->execute([$fileId, $user['user_id'], $user['user_id']]);
        $result = $stmt->fetch();
        
        if ($result && $result['count'] > 0) {
            $hasAccess = true;
        }
    }
    
    if (!$hasAccess) {
        sendJSON(['success' => false, 'error' => 'Access denied'], 403);
    }
    
    if (!file_exists($file['file_path'])) {
        sendJSON(['success' => false, 'error' => 'File missing on server'], 404);
    }
    
    $fp = fopen($file['file_path'], 'rb');
    $fileSize = $file['file_size'];
    $chunkSize = 1024 * 1024;
    
    header('Content-Type: ' . $file['mime_type']);
    header('Content-Length: ' . $fileSize);
    header('Content-Disposition: inline; filename="' . $file['filename'] . '"');
    header('Accept-Ranges: bytes');
    
    $range = $_SERVER['HTTP_RANGE'] ?? '';
    if ($range) {
        list($start, $end) = explode('-', substr($range, 6));
        $start = intval($start);
        $end = $end ? intval($end) : $fileSize - 1;
        
        header('HTTP/1.1 206 Partial Content');
        header("Content-Range: bytes $start-$end/$fileSize");
        header('Content-Length: ' . ($end - $start + 1));
        
        fseek($fp, $start);
        $remaining = $end - $start + 1;
        
        while ($remaining > 0 && !feof($fp)) {
            $read = min($chunkSize, $remaining);
            echo fread($fp, $read);
            $remaining -= $read;
            flush();
        }
    } else {
        while (!feof($fp)) {
            echo fread($fp, $chunkSize);
            flush();
        }
    }
    
    fclose($fp);
    exit;
}

function handleInfo() {
    $user = requireAuth();
    $fileId = intval($_GET['file_id'] ?? 0);
    
    if (!$fileId) {
        sendJSON(['success' => false, 'error' => 'Missing file_id'], 400);
    }
    
    $db = getDB();
    $stmt = $db->prepare("SELECT f.id, f.filename, f.file_size, f.mime_type, f.upload_time, u.username as owner FROM files f JOIN users u ON f.user_id = u.id WHERE f.id = ?");
    $stmt->execute([$fileId]);
    $file = $stmt->fetch();
    
    if (!$file) {
        sendJSON(['success' => false, 'error' => 'File not found'], 404);
    }
    
    sendJSON(['success' => true, 'file' => $file]);
}

function handleFileDelete() {
    $user = requireAuth();
    $data = getBody();
    $fileId = intval($data['file_id'] ?? 0);
    
    if (!$fileId) {
        sendJSON(['success' => false, 'error' => 'Missing file_id'], 400);
    }
    
    $db = getDB();
    $stmt = $db->prepare("SELECT file_path FROM files WHERE id = ? AND user_id = ?");
    $stmt->execute([$fileId, $user['user_id']]);
    $file = $stmt->fetch();
    
    if (!$file) {
        sendJSON(['success' => false, 'error' => 'File not found or unauthorized'], 404);
    }
    
    if (file_exists($file['file_path'])) {
        unlink($file['file_path']);
    }
    
    $stmt = $db->prepare("DELETE FROM files WHERE id = ?");
    $stmt->execute([$fileId]);
    
    sendJSON(['success' => true, 'message' => 'File deleted']);
}

function handleViewOnceUpload() {
    $user = requireAuth();
    
    if (!isset($_FILES['file'])) {
        sendJSON(['success' => false, 'error' => 'No file uploaded'], 400);
    }
    
    $file = $_FILES['file'];
    $recipientId = intval($_POST['recipient_id'] ?? 0);
    
    if (!$recipientId) {
        sendJSON(['success' => false, 'error' => 'Missing recipient_id'], 400);
    }
    
    $originalName = clean($file['name']);
    $fileSize = intval($file['size']);
    $tmpPath = $file['tmp_name'];
    
    if ($file['error'] !== UPLOAD_ERR_OK || $fileSize > MAX_FILE_SIZE) {
        sendJSON(['success' => false, 'error' => 'Upload failed'], 400);
    }
    
    $uploadDir = UPLOAD_DIR . '/viewonce/' . date('Y/m/d');
    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }
    
    $fileHash = hash_file('sha256', $tmpPath);
    $extension = pathinfo($originalName, PATHINFO_EXTENSION);
    $storedName = $fileHash . ($extension ? '.' . $extension : '');
    $storedPath = $uploadDir . '/' . $storedName;
    
    move_uploaded_file($tmpPath, $storedPath);
    
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO view_once_files (sender_id, recipient_id, original_name, stored_path, file_size, file_hash, mime_type, created_at, expires_at, is_viewed) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR), 0)");
    $stmt->execute([$user['user_id'], $recipientId, $originalName, $storedPath, $fileSize, $fileHash, $file['type']]);
    $fileId = $db->lastInsertId();
    
    sendJSON(['success' => true, 'file_id' => $fileId]);
}

function handleViewOnceDownload() {
    $user = requireAuth();
    $fileId = intval($_GET['file_id'] ?? 0);
    
    if (!$fileId) {
        sendJSON(['success' => false, 'error' => 'Missing file_id'], 400);
    }
    
    $db = getDB();
    $stmt = $db->prepare("SELECT * FROM view_once_files WHERE id = ? AND recipient_id = ?");
    $stmt->execute([$fileId, $user['user_id']]);
    $file = $stmt->fetch();
    
    if (!$file) {
        sendJSON(['success' => false, 'error' => 'File not found or unauthorized'], 404);
    }
    
    if ($file['is_viewed'] == 1) {
        sendJSON(['success' => false, 'error' => 'File already viewed'], 410);
    }
    
    if (strtotime($file['expires_at']) < time()) {
        sendJSON(['success' => false, 'error' => 'File expired'], 410);
    }
    
    if (!file_exists($file['stored_path'])) {
        sendJSON(['success' => false, 'error' => 'File missing on server'], 404);
    }
    
    $stmt = $db->prepare("UPDATE view_once_files SET is_viewed = 1, viewed_at = NOW() WHERE id = ?");
    $stmt->execute([$fileId]);
    
    header('Content-Type: ' . $file['mime_type']);
    header('Content-Length: ' . $file['file_size']);
    header('Content-Disposition: inline; filename="' . $file['original_name'] . '"');
    header('X-View-Once: true');
    
    readfile($file['stored_path']);
    
    unlink($file['stored_path']);
    
    exit;
}
