<?php
header('Content-Type: application/json');

// Database connection
$host = 'localhost';
$username = "u265056410_sparkup";
$password = "Sparkup@12345";
$dbname = "u265056410_sparkup";

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Get request method and action
    $method = $_SERVER['REQUEST_METHOD'];
    $action = isset($_GET['action']) ? $_GET['action'] : null;
    
    // Parse JSON request body for POST/PUT requests
    $requestBody = null;
    if ($method === 'POST' || $method === 'PUT') {
        $requestBody = json_decode(file_get_contents('php://input'), true);
    }
    
    switch ($action) {
        case 'get_all_tables':
            // Get all tables with their status
            $stmt = $pdo->query("SELECT t.*, 
                                       a.id as assignment_id, 
                                       a.user_email_1, 
                                       a.user_email_2, 
                                       a.time_slot, 
                                       a.status as assignment_status,
                                       a.start_time,
                                       a.end_time
                                FROM classroom_tables t
                                LEFT JOIN table_assignments a ON t.id = a.table_id AND a.status IN ('pending', 'active')
                                ORDER BY t.classroom, t.table_number");
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;
            
        case 'get_classroom_tables':
            // Get tables in a specific classroom
            if (!isset($_GET['classroom'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Classroom parameter required']);
                exit;
            }
            
            $stmt = $pdo->prepare("SELECT t.*, 
                                         a.id as assignment_id, 
                                         a.user_email_1, 
                                         a.user_email_2, 
                                         a.time_slot, 
                                         a.status as assignment_status,
                                         a.start_time,
                                         a.end_time
                                  FROM classroom_tables t
                                  LEFT JOIN table_assignments a ON t.id = a.table_id AND a.status IN ('pending', 'active')
                                  WHERE t.classroom = ?
                                  ORDER BY t.table_number");
            $stmt->execute([$_GET['classroom']]);
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;
            
        case 'assign_table':
            // Assign users to a table
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed']);
                exit;
            }
            
            if (!isset($requestBody['table_id']) || !isset($requestBody['user_email_1']) || 
                !isset($requestBody['user_email_2']) || !isset($requestBody['time_slot'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Missing required parameters']);
                exit;
            }
            
            $pdo->beginTransaction();
            try {
                // First, check if table is available
                $stmt = $pdo->prepare("SELECT * FROM classroom_tables WHERE id = ?");
                $stmt->execute([$requestBody['table_id']]);
                $table = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$table) {
                    throw new Exception('Table not found');
                }
                
                // Check if assignment already exists
                $stmt = $pdo->prepare("SELECT * FROM table_assignments 
                                       WHERE (user_email_1 = ? AND user_email_2 = ?) 
                                       OR (user_email_1 = ? AND user_email_2 = ?)
                                       AND time_slot = ?");
                $stmt->execute([
                    $requestBody['user_email_1'], $requestBody['user_email_2'],
                    $requestBody['user_email_2'], $requestBody['user_email_1'],
                    $requestBody['time_slot']
                ]);
                
                if ($stmt->rowCount() > 0) {
                    // Update existing assignment
                    $assignment = $stmt->fetch(PDO::FETCH_ASSOC);
                    $updateStmt = $pdo->prepare("UPDATE table_assignments 
                                                SET table_id = ?, status = 'pending'
                                                WHERE id = ?");
                    $updateStmt->execute([$requestBody['table_id'], $assignment['id']]);
                } else {
                    // Create new assignment
                    $insertStmt = $pdo->prepare("INSERT INTO table_assignments 
                                                (table_id, user_email_1, user_email_2, time_slot, status) 
                                                VALUES (?, ?, ?, ?, 'pending')");
                    $insertStmt->execute([
                        $requestBody['table_id'], 
                        $requestBody['user_email_1'],
                        $requestBody['user_email_2'],
                        $requestBody['time_slot']
                    ]);
                }
                
                // Update table status to reserved
                $updateTableStmt = $pdo->prepare("UPDATE classroom_tables SET status = 'reserved' WHERE id = ?");
                $updateTableStmt->execute([$requestBody['table_id']]);
                
                $pdo->commit();
                echo json_encode(['success' => true, 'message' => 'Table assigned successfully']);
            } catch (Exception $e) {
                $pdo->rollBack();
                http_response_code(500);
                echo json_encode(['error' => $e->getMessage()]);
            }
            break;
            
        case 'update_table_status':
            // Update a table's status
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed']);
                exit;
            }
            
            if (!isset($requestBody['table_id']) || !isset($requestBody['status'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Missing required parameters']);
                exit;
            }
            
            $validStatuses = ['available', 'occupied', 'reserved'];
            if (!in_array($requestBody['status'], $validStatuses)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid status value']);
                exit;
            }
            
            $stmt = $pdo->prepare("UPDATE classroom_tables SET status = ? WHERE id = ?");
            $stmt->execute([$requestBody['status'], $requestBody['table_id']]);
            
            echo json_encode(['success' => true, 'message' => 'Table status updated']);
            break;
            
        case 'get_active_conversations':
            // Get all active conversations
            $stmt = $pdo->query("SELECT a.*, t.classroom, t.table_number, 
                                       u1.first_name as user1_first_name, u1.last_name as user1_last_name,
                                       u2.first_name as user2_first_name, u2.last_name as user2_last_name,
                                       TIMESTAMPDIFF(SECOND, a.start_time, NOW()) as elapsed_seconds,
                                       TIMESTAMPDIFF(SECOND, a.start_time, IFNULL(a.end_time, NOW())) as duration_seconds,
                                       CASE 
                                           WHEN a.end_time IS NULL THEN 300 - TIMESTAMPDIFF(SECOND, a.start_time, NOW()) 
                                           ELSE 0 
                                       END as remaining_seconds
                                FROM table_assignments a
                                JOIN classroom_tables t ON a.table_id = t.id
                                LEFT JOIN users u1 ON a.user_email_1 = u1.email
                                LEFT JOIN users u2 ON a.user_email_2 = u2.email
                                WHERE a.status = 'active' AND a.start_time IS NOT NULL AND a.end_time IS NULL");
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;
            
        case 'get_upcoming_conversations':
            // Get upcoming conversations
            $stmt = $pdo->query("SELECT a.*, t.classroom, t.table_number,
                                       u1.first_name as user1_first_name, u1.last_name as user1_last_name,
                                       u2.first_name as user2_first_name, u2.last_name as user2_last_name
                                FROM table_assignments a
                                JOIN classroom_tables t ON a.table_id = t.id
                                LEFT JOIN users u1 ON a.user_email_1 = u1.email
                                LEFT JOIN users u2 ON a.user_email_2 = u2.email
                                WHERE a.status = 'pending'
                                ORDER BY a.time_slot");
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;
            
        case 'change_table':
            // Change table for an assignment
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed']);
                exit;
            }
            
            if (!isset($requestBody['assignment_id']) || !isset($requestBody['new_table_id'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Missing required parameters']);
                exit;
            }
            
            $pdo->beginTransaction();
            try {
                // Get current assignment
                $stmt = $pdo->prepare("SELECT * FROM table_assignments WHERE id = ?");
                $stmt->execute([$requestBody['assignment_id']]);
                $assignment = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$assignment) {
                    throw new Exception('Assignment not found');
                }
                
                // Free up old table
                $stmt = $pdo->prepare("UPDATE classroom_tables SET status = 'available' WHERE id = ?");
                $stmt->execute([$assignment['table_id']]);
                
                // Reserve new table
                $stmt = $pdo->prepare("UPDATE classroom_tables SET status = 'reserved' WHERE id = ?");
                $stmt->execute([$requestBody['new_table_id']]);
                
                // Update assignment
                $stmt = $pdo->prepare("UPDATE table_assignments SET table_id = ? WHERE id = ?");
                $stmt->execute([$requestBody['new_table_id'], $requestBody['assignment_id']]);
                
                $pdo->commit();
                echo json_encode(['success' => true, 'message' => 'Table changed successfully']);
            } catch (Exception $e) {
                $pdo->rollBack();
                http_response_code(500);
                echo json_encode(['error' => $e->getMessage()]);
            }
            break;
            
        case 'sync_qr_scan':
            // Sync QR scan with table assignments
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed']);
                exit;
            }
            
            if (!isset($requestBody['user_email_1']) || !isset($requestBody['user_email_2'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Missing required parameters']);
                exit;
            }
            
            $pdo->beginTransaction();
            try {
                // Find matching table assignment
                $stmt = $pdo->prepare("SELECT a.*, t.id as table_id 
                                       FROM table_assignments a
                                       JOIN classroom_tables t ON a.table_id = t.id
                                       WHERE ((a.user_email_1 = ? AND a.user_email_2 = ?) 
                                       OR (a.user_email_1 = ? AND a.user_email_2 = ?))
                                       AND a.status = 'pending'");
                $stmt->execute([
                    $requestBody['user_email_1'], $requestBody['user_email_2'],
                    $requestBody['user_email_2'], $requestBody['user_email_1']
                ]);
                
                $assignment = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$assignment) {
                    // If no assignment found, find any available table
                    $tableStmt = $pdo->query("SELECT id FROM classroom_tables WHERE status = 'available' LIMIT 1");
                    $availableTable = $tableStmt->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$availableTable) {
                        throw new Exception('No table assignments or available tables found');
                    }
                    
                    // Create a new assignment
                    $now = date('Y-m-d H:i:s');
                    $insertStmt = $pdo->prepare("INSERT INTO table_assignments 
                                                (table_id, user_email_1, user_email_2, time_slot, status, start_time) 
                                                VALUES (?, ?, ?, ?, 'active', ?)");
                    
                    $currentTimeSlot = date('H:i') . '-' . date('H:i', strtotime('+30 minutes'));
                    $insertStmt->execute([
                        $availableTable['id'], 
                        $requestBody['user_email_1'],
                        $requestBody['user_email_2'],
                        $currentTimeSlot,
                        $now
                    ]);
                    
                    $assignment = [
                        'id' => $pdo->lastInsertId(),
                        'table_id' => $availableTable['id']
                    ];
                } else {
                    // Update existing assignment
                    $updateStmt = $pdo->prepare("UPDATE table_assignments 
                                                SET status = 'active', start_time = ? 
                                                WHERE id = ?");
                    $updateStmt->execute([date('Y-m-d H:i:s'), $assignment['id']]);
                }
                
                // Update table status
                $updateTableStmt = $pdo->prepare("UPDATE classroom_tables SET status = 'occupied' WHERE id = ?");
                $updateTableStmt->execute([$assignment['table_id']]);
                
                // Update completed_matches with table assignment reference
                $updateMatchesStmt = $pdo->prepare("UPDATE completed_matches 
                                                   SET table_assignment_id = ? 
                                                   WHERE (user_email = ? AND match_email = ?)
                                                   OR (user_email = ? AND match_email = ?)");
                $updateMatchesStmt->execute([
                    $assignment['id'],
                    $requestBody['user_email_1'], $requestBody['user_email_2'],
                    $requestBody['user_email_2'], $requestBody['user_email_1']
                ]);
                
                $pdo->commit();
                echo json_encode([
                    'success' => true, 
                    'assignment_id' => $assignment['id'],
                    'message' => 'QR scan synced with table assignment'
                ]);
            } catch (Exception $e) {
                $pdo->rollBack();
                http_response_code(500);
                echo json_encode(['error' => $e->getMessage()]);
            }
            break;
            
        case 'end_conversation':
            // End a conversation (update assignment and table)
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed']);
                exit;
            }
            
            if (!isset($requestBody['user_email']) || !isset($requestBody['match_email'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Missing required parameters']);
                exit;
            }
            
            $pdo->beginTransaction();
            try {
                // Find table assignment
                $stmt = $pdo->prepare("SELECT a.*, t.id as table_id 
                                       FROM table_assignments a
                                       JOIN classroom_tables t ON a.table_id = t.id
                                       WHERE ((a.user_email_1 = ? AND a.user_email_2 = ?) 
                                       OR (a.user_email_1 = ? AND a.user_email_2 = ?))
                                       AND a.status = 'active'");
                $stmt->execute([
                    $requestBody['user_email'], $requestBody['match_email'],
                    $requestBody['match_email'], $requestBody['user_email']
                ]);
                
                $assignment = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$assignment) {
                    throw new Exception('No active conversation found');
                }
                
                // Update assignment
                $updateStmt = $pdo->prepare("UPDATE table_assignments 
                                             SET status = 'completed', end_time = ? 
                                             WHERE id = ?");
                $updateStmt->execute([date('Y-m-d H:i:s'), $assignment['id']]);
                
                // Update table status
                $updateTableStmt = $pdo->prepare("UPDATE classroom_tables SET status = 'available' WHERE id = ?");
                $updateTableStmt->execute([$assignment['table_id']]);
                
                // Update completed_matches
                $updateMatchesStmt = $pdo->prepare("UPDATE completed_matches 
                                                   SET end_time = ?, ended_early = 1, ended_by = ? 
                                                   WHERE (user_email = ? AND match_email = ?)
                                                   OR (user_email = ? AND match_email = ?)");
                $updateMatchesStmt->execute([
                    date('Y-m-d H:i:s'),
                    $requestBody['user_email'],
                    $requestBody['user_email'], $requestBody['match_email'],
                    $requestBody['match_email'], $requestBody['user_email']
                ]);
                
                $pdo->commit();
                echo json_encode([
                    'success' => true,
                    'message' => 'Conversation ended successfully'
                ]);
            } catch (Exception $e) {
                $pdo->rollBack();
                http_response_code(500);
                echo json_encode(['error' => $e->getMessage()]);
            }
            break;
            
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
    }
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
