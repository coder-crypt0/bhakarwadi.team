<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Database configuration
$host = 'localhost';
$dbname = 'u265056410_traffic';
$username = 'u265056410_traffic';
$password = 'Traffic@4321';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$request = explode('/', trim($_SERVER['PATH_INFO'] ?? '', '/'));

// Handle both GET and POST for browser testing
$data = array_merge($_GET, $_POST);

// If we have violation data in GET/POST, create violation
if (isset($data['violation_id']) && isset($data['license_plate'])) {
    createViolation($pdo, $data);
    exit;
}

switch($method) {
    case 'POST':
        if ($request[0] === 'create') {
            createViolation($pdo);
        } elseif ($request[0] === 'payment-success') {
            handlePaymentSuccess($pdo);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'GET':
        if ($request[0] === 'stats') {
            getStats($pdo);
        } elseif ($request[0] === 'list') {
            getViolations($pdo);
        } elseif ($request[0] === 'search') {
            searchViolations($pdo);
        } else {
            // Default: show API info
            echo json_encode([
                'success' => true,
                'message' => 'Violations API is working',
                'endpoint' => 'api/violations',
                'browser_test_urls' => [
                    'create_violation' => 'api/violations?violation_id=TEST123&license_plate=MH02DN8748&amount=500',
                    'stats' => 'api/violations/stats',
                    'list' => 'api/violations/list?limit=10',
                    'search' => 'api/violations/search?q=MH02'
                ]
            ]);
        }
        break;
        
    case 'PUT':
        if ($request[0] === 'update-status') {
            updateViolationStatus($pdo);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function createViolation($pdo, $data = null) {
    // Handle both JSON input and GET/POST data
    if ($data === null) {
        $input = json_decode(file_get_contents('php://input'), true);
    } else {
        $input = $data;
    }
    
    // Validate required fields
    $required = ['violation_id', 'license_plate', 'amount'];
    foreach ($required as $field) {
        if (!isset($input[$field]) || empty($input[$field])) {
            http_response_code(400);
            echo json_encode(['error' => "Missing required field: $field"]);
            return;
        }
    }
    
    try {
        $stmt = $pdo->prepare("
            INSERT INTO violations (
                violation_id, license_plate, amount, status, 
                cashfree_session_id, image_path, location, 
                violation_type, camera_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE
                license_plate = VALUES(license_plate),
                amount = VALUES(amount),
                status = VALUES(status),
                updated_at = NOW()
        ");
        
        $stmt->execute([
            $input['violation_id'],
            $input['license_plate'],
            $input['amount'],
            $input['status'] ?? 'pending',
            $input['cashfree_session_id'] ?? null,
            $input['image_path'] ?? null,
            $input['location'] ?? 'Traffic Signal Camera',
            $input['violation_type'] ?? 'Crossing Stop Line During Red Signal',
            $input['camera_id'] ?? 'CAMERA_01'
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Violation created successfully',
            'violation_id' => $input['violation_id']
        ]);
        
    } catch(PDOException $e) {
        if ($e->getCode() == 23000) { // Duplicate entry
            http_response_code(409);
            echo json_encode(['error' => 'Violation ID already exists']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
        }
    }
}

function handlePaymentSuccess($pdo) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['order_id']) || !isset($input['violation_id'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing order_id or violation_id']);
        return;
    }
    
    try {
        $stmt = $pdo->prepare("
            UPDATE violations 
            SET status = 'paid', paid_at = NOW(), payment_order_id = ? 
            WHERE violation_id = ?
        ");
        
        $stmt->execute([$input['order_id'], $input['violation_id']]);
        
        if ($stmt->rowCount() > 0) {
            echo json_encode([
                'success' => true,
                'message' => 'Payment status updated successfully'
            ]);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Violation not found']);
        }
        
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function getStats($pdo) {
    try {
        $stats = [
            'total' => $pdo->query("SELECT COUNT(*) FROM violations")->fetchColumn(),
            'paid' => $pdo->query("SELECT COUNT(*) FROM violations WHERE status = 'paid'")->fetchColumn(),
            'pending' => $pdo->query("SELECT COUNT(*) FROM violations WHERE status = 'pending'")->fetchColumn(),
            'revenue' => $pdo->query("SELECT COALESCE(SUM(amount), 0) FROM violations WHERE status = 'paid'")->fetchColumn(),
            'today_violations' => $pdo->query("SELECT COUNT(*) FROM violations WHERE DATE(created_at) = CURDATE()")->fetchColumn(),
            'today_revenue' => $pdo->query("SELECT COALESCE(SUM(amount), 0) FROM violations WHERE status = 'paid' AND DATE(paid_at) = CURDATE()")->fetchColumn()
        ];
        
        echo json_encode(['success' => true, 'data' => $stats]);
        
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function getViolations($pdo) {
    try {
        $limit = $_GET['limit'] ?? 50;
        $offset = $_GET['offset'] ?? 0;
        $status = $_GET['status'] ?? null;
        
        $sql = "SELECT * FROM violations";
        $params = [];
        
        if ($status) {
            $sql .= " WHERE status = ?";
            $params[] = $status;
        }
        
        $sql .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
        $params[] = (int)$limit;
        $params[] = (int)$offset;
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $violations = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode(['success' => true, 'data' => $violations]);
        
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function searchViolations($pdo) {
    try {
        $query = $_GET['q'] ?? '';
        if (empty($query)) {
            http_response_code(400);
            echo json_encode(['error' => 'Search query is required']);
            return;
        }
        
        $stmt = $pdo->prepare("
            SELECT * FROM violations 
            WHERE license_plate LIKE ? OR violation_id LIKE ? OR payment_order_id LIKE ?
            ORDER BY created_at DESC 
            LIMIT 20
        ");
        
        $searchTerm = "%$query%";
        $stmt->execute([$searchTerm, $searchTerm, $searchTerm]);
        $violations = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode(['success' => true, 'data' => $violations]);
        
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function updateViolationStatus($pdo) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['violation_id']) || !isset($input['status'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing violation_id or status']);
        return;
    }
    
    try {
        $stmt = $pdo->prepare("UPDATE violations SET status = ? WHERE violation_id = ?");
        $stmt->execute([$input['status'], $input['violation_id']]);
        
        if ($stmt->rowCount() > 0) {
            echo json_encode([
                'success' => true,
                'message' => 'Status updated successfully'
            ]);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Violation not found']);
        }
        
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}
?>
