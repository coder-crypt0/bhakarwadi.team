<?php
/**
 * User Management API
 * Endpoints: ?action=search, ?action=profile, ?action=contacts-list, etc.
 */

require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

switch ($action) {
    case 'search':
        $method === 'GET' ? handleSearch() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'profile':
        if ($method === 'GET') handleGetProfile();
        elseif ($method === 'PUT') handleUpdateProfile();
        else sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'contacts-list':
        $method === 'GET' ? handleListContacts() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'contacts-add':
        $method === 'POST' ? handleAddContact() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'contacts-remove':
        $method === 'DELETE' ? handleRemoveContact() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'block':
        $method === 'POST' ? handleBlock() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'unblock':
        $method === 'POST' ? handleUnblock() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'exchange-key':
        $method === 'POST' ? handleKeyExchange() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    case 'get-public-key':
        $method === 'GET' ? handleGetPublicKey() : sendJSON(['success' => false, 'error' => 'Method not allowed'], 405);
        break;
    default:
        sendJSON(['success' => false, 'error' => 'Endpoint not found'], 404);
}

function handleSearch() {
    $user = requireAuth();
    $query = clean($_GET['q'] ?? '');
    
    if (strlen($query) < 2) {
        sendJSON(['success' => false, 'error' => 'Query too short'], 400);
    }
    
    $db = getDB();
    $stmt = $db->prepare("SELECT id, username, email FROM users WHERE (username LIKE ? OR email LIKE ?) AND id != ? AND is_active = 1 LIMIT 50");
    $searchTerm = "%$query%";
    $stmt->execute([$searchTerm, $searchTerm, $user['user_id']]);
    $users = $stmt->fetchAll();
    
    sendJSON(['success' => true, 'users' => $users]);
}

function handleGetProfile() {
    $user = requireAuth();
    
    $db = getDB();
    $stmt = $db->prepare("SELECT id, username, email, created_at, last_login FROM users WHERE id = ?");
    $stmt->execute([$user['user_id']]);
    $profile = $stmt->fetch();
    
    if (!$profile) {
        sendJSON(['success' => false, 'error' => 'User not found'], 404);
    }
    
    sendJSON(['success' => true, 'user' => $profile]);
}

function handleUpdateProfile() {
    $user = requireAuth();
    $data = getBody();
    
    $updates = [];
    $params = [];
    
    if (isset($data['username'])) {
        $username = clean($data['username']);
        if (strlen($username) < 3) {
            sendJSON(['success' => false, 'error' => 'Username too short'], 400);
        }
        $updates[] = "username = ?";
        $params[] = $username;
    }
    
    if (isset($data['password'])) {
        $password = $data['password'];
        if (strlen($password) < 8) {
            sendJSON(['success' => false, 'error' => 'Password too short'], 400);
        }
        $updates[] = "password_hash = ?";
        $params[] = password_hash($password, PASSWORD_BCRYPT, ['cost' => PASSWORD_HASH_COST]);
    }
    
    if (empty($updates)) {
        sendJSON(['success' => false, 'error' => 'No fields to update'], 400);
    }
    
    $params[] = $user['user_id'];
    
    $db = getDB();
    $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    sendJSON(['success' => true, 'message' => 'Profile updated']);
}

function handleListContacts() {
    $user = requireAuth();
    
    $db = getDB();
    // Note: database uses contact_id and is_blocked, not contact_user_id and status
    $stmt = $db->prepare("SELECT c.id, c.contact_id as contact_user_id, u.username, u.email FROM contacts c JOIN users u ON c.contact_id = u.id WHERE c.user_id = ? AND c.is_blocked = 0 ORDER BY u.username");
    $stmt->execute([$user['user_id']]);
    $contacts = $stmt->fetchAll();
    
    sendJSON(['success' => true, 'contacts' => $contacts]);
}

function handleAddContact() {
    $user = requireAuth();
    $data = getBody();
    $contactId = intval($data['user_id'] ?? 0);
    
    if (!$contactId) {
        sendJSON(['success' => false, 'error' => 'Invalid user_id'], 400);
    }
    
    if ($contactId === $user['user_id']) {
        sendJSON(['success' => false, 'error' => 'Cannot add yourself'], 400);
    }
    
    $db = getDB();
    
    $stmt = $db->prepare("SELECT id FROM users WHERE id = ?");
    $stmt->execute([$contactId]);
    if (!$stmt->fetch()) {
        sendJSON(['success' => false, 'error' => 'User not found'], 404);
    }
    
    // Note: database uses contact_id, not contact_user_id
    $stmt = $db->prepare("SELECT id FROM contacts WHERE user_id = ? AND contact_id = ?");
    $stmt->execute([$user['user_id'], $contactId]);
    if ($stmt->fetch()) {
        sendJSON(['success' => false, 'error' => 'Already in contacts'], 400);
    }
    
    // Note: database uses contact_id and added_at, not contact_user_id and created_at
    $stmt = $db->prepare("INSERT INTO contacts (user_id, contact_id, added_at, is_blocked) VALUES (?, ?, NOW(), 0)");
    $stmt->execute([$user['user_id'], $contactId]);
    
    sendJSON(['success' => true, 'message' => 'Contact added']);
}

function handleRemoveContact() {
    $user = requireAuth();
    $data = getBody();
    $contactId = intval($data['user_id'] ?? 0);
    
    if (!$contactId) {
        sendJSON(['success' => false, 'error' => 'Invalid user_id'], 400);
    }
    
    $db = getDB();
    // Note: database uses contact_id, not contact_user_id
    $stmt = $db->prepare("DELETE FROM contacts WHERE user_id = ? AND contact_id = ?");
    $stmt->execute([$user['user_id'], $contactId]);
    
    if ($stmt->rowCount() === 0) {
        sendJSON(['success' => false, 'error' => 'Contact not found'], 404);
    }
    
    sendJSON(['success' => true, 'message' => 'Contact removed']);
}

function handleBlock() {
    $user = requireAuth();
    $data = getBody();
    $blockId = intval($data['user_id'] ?? 0);
    
    if (!$blockId || $blockId === $user['user_id']) {
        sendJSON(['success' => false, 'error' => 'Invalid user_id'], 400);
    }
    
    $db = getDB();
    
    // Note: database uses contact_id and is_blocked, not contact_user_id and status
    $stmt = $db->prepare("SELECT id, is_blocked FROM contacts WHERE user_id = ? AND contact_id = ?");
    $stmt->execute([$user['user_id'], $blockId]);
    $existing = $stmt->fetch();
    
    if ($existing) {
        $stmt = $db->prepare("UPDATE contacts SET is_blocked = 1, blocked_at = NOW() WHERE id = ?");
        $stmt->execute([$existing['id']]);
    } else {
        $stmt = $db->prepare("INSERT INTO contacts (user_id, contact_id, is_blocked, added_at, blocked_at) VALUES (?, ?, 1, NOW(), NOW())");
        $stmt->execute([$user['user_id'], $blockId]);
    }
    
    sendJSON(['success' => true, 'message' => 'User blocked']);
}

function handleUnblock() {
    $user = requireAuth();
    $data = getBody();
    $unblockId = intval($data['user_id'] ?? 0);
    
    if (!$unblockId) {
        sendJSON(['success' => false, 'error' => 'Invalid user_id'], 400);
    }
    
    $db = getDB();
    // Note: database uses contact_id and is_blocked
    $stmt = $db->prepare("DELETE FROM contacts WHERE user_id = ? AND contact_id = ? AND is_blocked = 1");
    $stmt->execute([$user['user_id'], $unblockId]);
    
    if ($stmt->rowCount() === 0) {
        sendJSON(['success' => false, 'error' => 'User not blocked'], 400);
    }
    
    sendJSON(['success' => true, 'message' => 'User unblocked']);
}

function handleKeyExchange() {
    $user = requireAuth();
    $data = getBody();
    $publicKey = clean($data['public_key'] ?? '');
    
    if (!$publicKey) {
        sendJSON(['success' => false, 'error' => 'Missing public_key'], 400);
    }
    
    // Store public key temporarily (expires in 60 seconds - ephemeral)
    $db = getDB();
    
    // Delete old key if exists
    $stmt = $db->prepare("DELETE FROM user_public_keys WHERE user_id = ?");
    $stmt->execute([$user['user_id']]);
    
    // Insert new public key with expiration
    $stmt = $db->prepare("INSERT INTO user_public_keys (user_id, public_key, created_at, expires_at) VALUES (?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 60 SECOND))");
    $stmt->execute([$user['user_id'], $publicKey]);
    
    sendJSON(['success' => true, 'message' => 'Public key stored']);
}

function handleGetPublicKey() {
    $user = requireAuth();
    $userId = intval($_GET['user_id'] ?? 0);
    
    if (!$userId) {
        sendJSON(['success' => false, 'error' => 'Missing user_id'], 400);
    }
    
    $db = getDB();
    
    // Get public key if not expired
    $stmt = $db->prepare("SELECT public_key FROM user_public_keys WHERE user_id = ? AND expires_at > NOW()");
    $stmt->execute([$userId]);
    $result = $stmt->fetch();
    
    if (!$result) {
        sendJSON(['success' => false, 'error' => 'Public key not found or expired'], 404);
    }
    
    sendJSON(['success' => true, 'public_key' => $result['public_key']]);
}
