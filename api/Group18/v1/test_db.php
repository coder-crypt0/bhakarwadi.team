<?php
// Test database connection and INSERT
require_once 'config.php';

header('Content-Type: application/json');

try {
    $db = getDB();
    echo json_encode(['success' => true, 'message' => 'DB connected']);
    
    // Test insert
    $stmt = $db->prepare("INSERT INTO users (email, username, password_hash, is_verified, created_at) VALUES (?, ?, ?, 1, NOW())");
    $result = $stmt->execute(['test_' . time() . '@test.com', 'test_' . time(), 'hash123']);
    
    echo json_encode(['success' => true, 'message' => 'Insert OK', 'id' => $db->lastInsertId()]);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
