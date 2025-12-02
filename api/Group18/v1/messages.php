<?php
/**
 * Messaging API
 * Endpoints: ?action=send, ?action=inbox, ?action=history, ?action=global-send, ?action=global-messages, ?action=delete
 */

require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// AUTO-DELETE old messages (ephemeral messaging)
// Messages older than 60 seconds are permanently deleted
function autoDeleteExpiredMessages() {
    try {
        $db = getDB();
        
        // Delete private messages older than 60 seconds
        $stmt = $db->prepare("DELETE FROM messages WHERE timestamp < DATE_SUB(NOW(), INTERVAL 60 SECOND)");
        $stmt->execute();
        $deletedPrivate = $stmt->rowCount();
        
        // Delete global chat messages older than 60 seconds
        $stmt = $db->prepare("DELETE FROM global_chat WHERE timestamp < DATE_SUB(NOW(), INTERVAL 60 SECOND)");
        $stmt->execute();
        $deletedGlobal = $stmt->rowCount();
        
        // Delete expired public keys (backup in case MySQL events disabled)
        $stmt = $db->prepare("DELETE FROM user_public_keys WHERE expires_at < NOW()");
        $stmt->execute();
        $deletedKeys = $stmt->rowCount();
        
        if ($deletedPrivate > 0 || $deletedGlobal > 0 || $deletedKeys > 0) {
            error_log("[EPHEMERAL] Auto-deleted $deletedPrivate private + $deletedGlobal global messages + $deletedKeys expired keys");
        }
    } catch (Exception $e) {
        error_log("[EPHEMERAL] Auto-delete failed: " . $e->getMessage());
    }
}

// Call auto-delete on EVERY request
autoDeleteExpiredMessages();

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

switch ($action) {
    case 'send':
        $method === 'POST' ? handleSend() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'inbox':
        $method === 'GET' ? handleInbox() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'history':
        $method === 'GET' ? handleHistory() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'global-send':
        $method === 'POST' ? handleGlobalSend() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'global-messages':
        $method === 'GET' ? handleGlobalMessages() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'delete':
        $method === 'DELETE' ? handleDelete() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    default:
        sendJSON(['success' => false, 'error' => 'Endpoint not found'], 404);
}

function handleSend() {
    $user = requireAuth();
    $data = getBody();
    
    $recipientId = intval($data['recipient_id'] ?? 0);
    $encryptedMsg = clean($data['encrypted_message'] ?? '');
    $messageType = clean($data['message_type'] ?? 'text');
    $fileUrl = isset($data['file_url']) ? clean($data['file_url']) : null;
    $fileId = isset($data['file_id']) ? intval($data['file_id']) : null;
    
    if (!$recipientId || !$encryptedMsg) {
        sendJSON(['success' => false, 'error' => 'Missing required fields'], 400);
    }
    
    if ($recipientId === $user['user_id']) {
        sendJSON(['success' => false, 'error' => 'Cannot message yourself'], 400);
    }
    
    $db = getDB();
    
    $stmt = $db->prepare("SELECT id FROM users WHERE id = ?");
    $stmt->execute([$recipientId]);
    if (!$stmt->fetch()) {
        sendJSON(['success' => false, 'error' => 'Recipient not found'], 404);
    }
    
    // Check if sender is blocked
    $stmt = $db->prepare("SELECT id FROM contacts WHERE user_id = ? AND contact_id = ? AND is_blocked = 1");
    $stmt->execute([$recipientId, $user['user_id']]);
    if ($stmt->fetch()) {
        sendJSON(['success' => false, 'error' => 'You are blocked by this user'], 403);
    }
    
    // Note: database uses 'receiver_id' not 'recipient_id'
    $stmt = $db->prepare("INSERT INTO messages (sender_id, receiver_id, encrypted_content, message_type, file_url, file_id, timestamp, is_read) VALUES (?, ?, ?, ?, ?, ?, NOW(), 0)");
    $stmt->execute([$user['user_id'], $recipientId, $encryptedMsg, $messageType, $fileUrl, $fileId]);
    $messageId = $db->lastInsertId();
    
    sendJSON(['success' => true, 'message_id' => $messageId]);
}

function handleInbox() {
    $user = requireAuth();
    $limit = intval($_GET['limit'] ?? 50);
    $offset = intval($_GET['offset'] ?? 0);
    
    $db = getDB();
    // Note: database uses 'receiver_id' not 'recipient_id'
    $stmt = $db->prepare("SELECT m.id, m.sender_id, u.username as sender_username, m.encrypted_content, m.message_type, m.file_url, m.timestamp as created_at, m.is_read, f.id as file_id, f.filename as file_name, f.file_size FROM messages m JOIN users u ON m.sender_id = u.id LEFT JOIN files f ON m.file_id = f.id WHERE m.receiver_id = ? ORDER BY m.timestamp DESC LIMIT ? OFFSET ?");
    $stmt->execute([$user['user_id'], $limit, $offset]);
    $messages = $stmt->fetchAll();
    
    $stmt = $db->prepare("SELECT COUNT(*) as count FROM messages WHERE receiver_id = ?");
    $stmt->execute([$user['user_id']]);
    $total = $stmt->fetch()['count'];
    
    // EPHEMERAL: Don't delete immediately - let the 60-second auto-delete handle it
    // This gives clients time to fetch messages even with polling delays
    
    sendJSON(['success' => true, 'messages' => $messages, 'total' => $total]);
}

function handleHistory() {
    $user = requireAuth();
    $contactId = intval($_GET['user_id'] ?? 0);
    $limit = intval($_GET['limit'] ?? 50);
    $offset = intval($_GET['offset'] ?? 0);
    
    if (!$contactId) {
        sendJSON(['success' => false, 'error' => 'Missing user_id'], 400);
    }
    
    $db = getDB();
    // Note: database uses 'receiver_id' not 'recipient_id'
    // ORDER BY ASC so oldest messages come first (client tracks lastDisplayedMessageId)
    $stmt = $db->prepare("SELECT m.id, m.sender_id, m.receiver_id as recipient_id, u.username as sender_username, m.encrypted_content, m.message_type, m.file_url, m.timestamp as created_at, m.is_read, f.id as file_id, f.filename as file_name, f.file_size FROM messages m JOIN users u ON m.sender_id = u.id LEFT JOIN files f ON m.file_id = f.id WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?) ORDER BY m.timestamp ASC LIMIT ? OFFSET ?");
    $stmt->execute([$user['user_id'], $contactId, $contactId, $user['user_id'], $limit, $offset]);
    $messages = $stmt->fetchAll();
    
    // EPHEMERAL: Don't delete immediately - let the 60-second auto-delete handle it
    // This gives clients time to fetch messages even with polling delays
    // Client-side deduplication (lastDisplayedMessageId) prevents showing duplicates
    
    sendJSON(['success' => true, 'messages' => $messages]);
}

function handleGlobalSend() {
    $user = requireAuth();
    $data = getBody();
    
    $encryptedMsg = clean($data['encrypted_message'] ?? '');
    
    if (!$encryptedMsg) {
        sendJSON(['success' => false, 'error' => 'Missing encrypted_message'], 400);
    }
    
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO global_chat (user_id, encrypted_message, timestamp, message_type) VALUES (?, ?, NOW(), 'text')");
    $stmt->execute([$user['user_id'], $encryptedMsg]);
    $messageId = $db->lastInsertId();
    
    sendJSON(['success' => true, 'message_id' => $messageId]);
}

function handleGlobalMessages() {
    $user = requireAuth();
    $limit = intval($_GET['limit'] ?? 100);
    $offset = intval($_GET['offset'] ?? 0);
    $since = clean($_GET['since'] ?? '');
    
    $db = getDB();
    
    if ($since) {
        $stmt = $db->prepare("SELECT g.id, g.user_id, u.username, g.encrypted_message as encrypted_content, g.timestamp as created_at FROM global_chat g JOIN users u ON g.user_id = u.id WHERE g.timestamp > ? AND g.is_deleted = 0 ORDER BY g.timestamp ASC LIMIT ?");
        $stmt->execute([$since, $limit]);
    } else {
        $stmt = $db->prepare("SELECT g.id, g.user_id, u.username, g.encrypted_message as encrypted_content, g.timestamp as created_at FROM global_chat g JOIN users u ON g.user_id = u.id WHERE g.is_deleted = 0 ORDER BY g.timestamp DESC LIMIT ? OFFSET ?");
        $stmt->execute([$limit, $offset]);
        $messages = $stmt->fetchAll();
        $messages = array_reverse($messages);
        sendJSON(['success' => true, 'messages' => $messages]);
        return;
    }
    
    $messages = $stmt->fetchAll();
    sendJSON(['success' => true, 'messages' => $messages]);
}

function handleDelete() {
    $user = requireAuth();
    $data = getBody();
    $messageId = intval($data['message_id'] ?? 0);
    
    if (!$messageId) {
        sendJSON(['success' => false, 'error' => 'Missing message_id'], 400);
    }
    
    $db = getDB();
    $stmt = $db->prepare("DELETE FROM messages WHERE id = ? AND (sender_id = ? OR recipient_id = ?)");
    $stmt->execute([$messageId, $user['user_id'], $user['user_id']]);
    
    if ($stmt->rowCount() === 0) {
        sendJSON(['success' => false, 'error' => 'Message not found or unauthorized'], 404);
    }
    
    sendJSON(['success' => true, 'message' => 'Message deleted']);
}
