<?php
// Enable full error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', 'api_errors.log');

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

function debug_log($message) {
    error_log(print_r($message, true));
}

try {
    debug_log("API Request received");
    debug_log($_SERVER['REQUEST_METHOD'] . " " . $_SERVER['REQUEST_URI']);

    // Database connection
    $host = 'localhost';
    $db   = 'u265056410_IRCTC_Psap';
    $user = 'u265056410_IRCTC_Psap';
    $pass = 'IRCTC_Psap@1234';

    debug_log("Attempting database connection...");
    
    $conn = mysqli_connect($host, $user, $pass, $db);
    if (!$conn) {
        throw new Exception("Connection failed: " . mysqli_connect_error());
    }

    debug_log("Database connected successfully");

    // Get request parameters
    $method = $_SERVER['REQUEST_METHOD'];
    $action = isset($_GET['action']) ? $_GET['action'] : '';
    
    debug_log("Method: $method, Action: $action");

    if ($action === 'search_trains') {
        $source = mysqli_real_escape_string($conn, $_GET['source']);
        $dest = mysqli_real_escape_string($conn, $_GET['destination']);
        
        debug_log("Searching trains from $source to $dest");

        // First verify if the stations table exists
        $table_check = mysqli_query($conn, "SHOW TABLES LIKE 'stations'");
        if (!$table_check || mysqli_num_rows($table_check) == 0) {
            throw new Exception("Stations table does not exist");
        }

        // Verify if station codes exist
        $station_check = "SELECT station_name FROM stations WHERE station_code IN ('$source', '$dest')";
        $check_result = mysqli_query($conn, $station_check);
        
        if (!$check_result) {
            throw new Exception("Station check failed: " . mysqli_error($conn));
        }
        
        if (mysqli_num_rows($check_result) < 2) {
            throw new Exception("One or both station codes not found");
        }

        // Search for trains
        $sql = "SELECT t.*, 
                s1.station_name as source_name, 
                s1.station_code as source_code,
                s2.station_name as dest_name, 
                s2.station_code as dest_code,
                t.available_ac1,
                t.available_ac2,
                t.available_sl,
                t.fare_ac1,
                t.fare_ac2,
                t.fare_sl
                FROM trains t
                INNER JOIN stations s1 ON t.source = s1.station_name
                INNER JOIN stations s2 ON t.destination = s2.station_name
                WHERE s1.station_code = '$source' 
                AND s2.station_code = '$dest'";

        debug_log("Executing query: $sql");

        $result = mysqli_query($conn, $sql);
        if (!$result) {
            throw new Exception("Query failed: " . mysqli_error($conn));
        }

        $trains = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $trains[] = $row;
        }

        debug_log("Found " . count($trains) . " trains");

        echo json_encode([
            'success' => true,
            'data' => $trains,
            'debug' => [
                'source' => $source,
                'destination' => $dest,
                'query' => $sql,
                'found' => count($trains)
            ]
        ]);
    } 
    // Add new endpoint for checking bookings
    else if ($action === 'check_booking') {
        $pnr = mysqli_real_escape_string($conn, $_GET['pnr']);
        
        $sql = "SELECT b.*, t.train_name, t.train_number, t.source, t.destination, 
                t.departure_time, t.arrival_time, b.coach_type, b.seat_number, 
                b.food_preference, b.status, p.amount as paid_amount
                FROM bookings b
                JOIN trains t ON b.train_id = t.train_id
                LEFT JOIN payments p ON b.booking_id = p.booking_id
                WHERE b.pnr = '$pnr'";
                
        $result = mysqli_query($conn, $sql);
        if ($result && $row = mysqli_fetch_assoc($result)) {
            echo json_encode([
                'success' => true,
                'booking' => [
                    'pnr' => $row['pnr'],
                    'train_name' => $row['train_name'],
                    'train_number' => $row['train_number'],
                    'source' => $row['source'],
                    'destination' => $row['destination'],
                    'departure_time' => $row['departure_time'],
                    'coach_type' => $row['coach_type'],
                    'seat_number' => $row['seat_number'],
                    'status' => $row['status'],
                    'food_preference' => $row['food_preference'],
                    'amount_paid' => $row['paid_amount']
                ]
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'error' => 'Booking not found'
            ]);
        }
    }
    // Add new endpoint for cancelling booking
    else if ($action === 'cancel_booking') {
        $pnr = mysqli_real_escape_string($conn, $_GET['pnr']);
        
        $sql = "UPDATE bookings SET status = 'CANCELLED' WHERE pnr = '$pnr'";
        if (mysqli_query($conn, $sql)) {
            echo json_encode([
                'success' => true,
                'message' => 'Booking cancelled successfully'
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'error' => 'Failed to cancel booking'
            ]);
        }
    }
    // Add new endpoint for creating booking
    else if ($action === 'create_booking') {
        $train_id = mysqli_real_escape_string($conn, $_GET['train_id']);
        $name = mysqli_real_escape_string($conn, $_GET['name']);
        $mobile = mysqli_real_escape_string($conn, $_GET['mobile']);
        $email = mysqli_real_escape_string($conn, $_GET['email']);
        $class_type = mysqli_real_escape_string($conn, $_GET['class_type']);
        $num_tickets = (int)$_GET['num_tickets'];
        
        // Generate PNR
        $pnr = 'PNR' . rand(1000000, 9999999);
        
        // Insert booking
        $sql = "INSERT INTO bookings (train_id, passenger_name, mobile, email, 
                coach_type, num_tickets, booking_date, status, pnr) 
                VALUES ('$train_id', '$name', '$mobile', '$email', 
                '$class_type', $num_tickets, CURDATE(), 'CONFIRMED', '$pnr')";
        
        if (mysqli_query($conn, $sql)) {
            // Get booking details for response
            $sql = "SELECT b.*, t.train_name, t.train_number, t.source, t.destination,
                    t.departure_time, t.arrival_time
                    FROM bookings b
                    JOIN trains t ON b.train_id = t.train_id
                    WHERE b.pnr = '$pnr'";
            
            $result = mysqli_query($conn, $sql);
            $booking = mysqli_fetch_assoc($result);
            
            echo json_encode([
                'success' => true,
                'booking' => $booking
            ]);
        } else {
            throw new Exception("Failed to create booking: " . mysqli_error($conn));
        }
    }
    else {
        throw new Exception("Invalid action specified");
    }

} catch (Exception $e) {
    debug_log("Error occurred: " . $e->getMessage());
    debug_log("Stack trace: " . $e->getTraceAsString());

    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'debug' => [
            'file' => basename(__FILE__),
            'line' => $e->getLine(),
            'trace' => $e->getTraceAsString()
        ]
    ]);
}

if (isset($conn)) {
    mysqli_close($conn);
}
?>
