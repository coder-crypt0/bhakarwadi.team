<?php
/**
 * File Upload/Download API
 * Endpoints: ?action=upload, ?action=download, ?action=info, ?action=delete, ?action=stream, ?action=view-once
 * Uses Vercel Blob Storage for file storage
 */

require_once 'config.php';

// Vercel Blob Storage configuration
define('VERCEL_BLOB_TOKEN', 'vercel_blob_rw_0AMT5iI6XxJ19D4B_VyBSR0E7Hx0t5sZ9R7XCAke3TtoiA3');
define('VERCEL_BLOB_API', 'https://blob.vercel-storage.com');

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

/**
 * Upload file to Vercel Blob Storage
 */
function uploadToBlob($filename, $fileData, $contentType) {
    $url = VERCEL_BLOB_API . '/' . urlencode($filename);
    
    $headers = [
        'Authorization: Bearer ' . VERCEL_BLOB_TOKEN,
        'Content-Type: ' . $contentType,
        'x-content-type: ' . $contentType,
        'x-add-random-suffix: 1'
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $fileData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error || $httpCode !== 200) {
        error_log("Vercel Blob upload failed: $error - HTTP $httpCode - Response: $response");
        return null;
    }
    
    $result = json_decode($response, true);
    return $result['url'] ?? null;
}

/**
 * Download file from Vercel Blob Storage
 */
function downloadFromBlob($blobUrl) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $blobUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    $fileData = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error || $httpCode !== 200) {
        error_log("Vercel Blob download failed: $error - HTTP $httpCode");
        return null;
    }
    
    return $fileData;
}

/**
 * Delete file from Vercel Blob Storage
 */
function deleteFromBlob($blobUrl) {
    $data = json_encode(['urls' => [$blobUrl]]);
    
    $headers = [
        'Authorization: Bearer ' . VERCEL_BLOB_TOKEN,
        'Content-Type: application/json'
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, VERCEL_BLOB_API . '/delete');
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error || $httpCode !== 200) {
        error_log("Vercel Blob delete failed: $error - HTTP $httpCode");
        return false;
    }
    
    return true;
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
    
    // For encrypted files, hash the encrypted content; for normal files, hash the uploaded file
    if ($isEncrypted) {
        $fileHash = hash('sha256', $actualFileData);
        $uploadData = $actualFileData;
    } else {
        $fileHash = hash_file('sha256', $tmpPath);
        $uploadData = file_get_contents($tmpPath);
    }
    
    $extension = pathinfo($originalName, PATHINFO_EXTENSION);
    $blobFilename = 'tornado/' . date('Y/m/d') . '/' . $fileHash . ($extension ? '.' . $extension : '');
    
    // Upload to Vercel Blob Storage
    $blobUrl = uploadToBlob($blobFilename, $uploadData, $file['type']);
    
    if (!$blobUrl) {
        sendJSON(['success' => false, 'error' => 'Failed to upload to storage'], 500);
    }
    
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO files (user_id, filename, file_path, file_size, mime_type, upload_time) VALUES (?, ?, ?, ?, ?, NOW())");
    $stmt->execute([$user['user_id'], $originalName, $blobUrl, $fileSize, $file['type']]);
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
    
    // Download from Vercel Blob Storage
    $fileData = downloadFromBlob($file['file_path']);
    
    if ($fileData === null) {
        sendJSON(['success' => false, 'error' => 'File missing on server'], 404);
    }
    
    header('Content-Type: ' . $file['mime_type']);
    header('Content-Length: ' . strlen($fileData));
    header('Content-Disposition: attachment; filename="' . $file['filename'] . '"');
    
    echo $fileData;
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
    
    // Download from Vercel Blob Storage
    $fileData = downloadFromBlob($file['file_path']);
    
    if ($fileData === null) {
        sendJSON(['success' => false, 'error' => 'File missing on server'], 404);
    }
    
    $fileSize = strlen($fileData);
    
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
        
        echo substr($fileData, $start, $end - $start + 1);
    } else {
        echo $fileData;
    }
    
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
    
    // Delete from Vercel Blob Storage
    deleteFromBlob($file['file_path']);
    
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
    
    $fileHash = hash_file('sha256', $tmpPath);
    $extension = pathinfo($originalName, PATHINFO_EXTENSION);
    $blobFilename = 'tornado/viewonce/' . date('Y/m/d') . '/' . $fileHash . ($extension ? '.' . $extension : '');
    
    // Upload to Vercel Blob Storage
    $fileData = file_get_contents($tmpPath);
    $blobUrl = uploadToBlob($blobFilename, $fileData, $file['type']);
    
    if (!$blobUrl) {
        sendJSON(['success' => false, 'error' => 'Failed to upload to storage'], 500);
    }
    
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO view_once_files (sender_id, recipient_id, original_name, stored_path, file_size, file_hash, mime_type, created_at, expires_at, is_viewed) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR), 0)");
    $stmt->execute([$user['user_id'], $recipientId, $originalName, $blobUrl, $fileSize, $fileHash, $file['type']]);
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
    
    // Download from Vercel Blob Storage
    $fileData = downloadFromBlob($file['stored_path']);
    
    if ($fileData === null) {
        sendJSON(['success' => false, 'error' => 'File missing on server'], 404);
    }
    
    $stmt = $db->prepare("UPDATE view_once_files SET is_viewed = 1, viewed_at = NOW() WHERE id = ?");
    $stmt->execute([$fileId]);
    
    header('Content-Type: ' . $file['mime_type']);
    header('Content-Length: ' . strlen($fileData));
    header('Content-Disposition: inline; filename="' . $file['original_name'] . '"');
    header('X-View-Once: true');
    
    echo $fileData;
    
    // Delete from Vercel Blob Storage after viewing
    deleteFromBlob($file['stored_path']);
    
    exit;
}
