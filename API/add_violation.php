<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');

// Simple API endpoint for adding violations - fallback for Python script
$host = 'localhost';
$dbname = 'u265056410_traffic';
$username = 'u265056410_traffic';
$password = 'Traffic@4321';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// Get parameters from either GET or POST
$violation_id = $_REQUEST['violation_id'] ?? '';
$license_plate = $_REQUEST['license_plate'] ?? '';
$amount = $_REQUEST['amount'] ?? 500;
$status = $_REQUEST['status'] ?? 'pending';
$image_path = $_REQUEST['image_path'] ?? '';
$location = $_REQUEST['location'] ?? 'Traffic Signal Camera';
$violation_type = $_REQUEST['violation_type'] ?? 'Crossing Stop Line During Red Signal';
$camera_id = $_REQUEST['camera_id'] ?? 'CAMERA_01';

// Validate required fields
if (empty($violation_id) || empty($license_plate)) {
    echo json_encode(['error' => 'Missing required fields: violation_id, license_plate']);
    exit;
}

try {
    $stmt = $pdo->prepare("
        INSERT INTO violations (
            violation_id, license_plate, amount, status, 
            image_path, location, violation_type, camera_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE
        license_plate = VALUES(license_plate),
        amount = VALUES(amount),
        status = VALUES(status)
    ");
    
    $stmt->execute([
        $violation_id,
        $license_plate,
        floatval($amount),
        $status,
        $image_path,
        $location,
        $violation_type,
        $camera_id
    ]);
    
    echo json_encode([
        'success' => true,
        'message' => 'Violation added successfully',
        'violation_id' => $violation_id,
        'method' => 'simple_api'
    ]);
    
} catch(PDOException $e) {
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>
