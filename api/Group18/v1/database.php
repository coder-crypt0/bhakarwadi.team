<?php
/**
 * Tornado Messenger Database Connection Handler
 * Version 1.0.0 - Group 18
 */

require_once 'config.php';

class Database {
    private static $instance = null;
    private $connection;
    private $host;
    private $dbname;
    private $username;
    private $password;
    private $charset;

    private function __construct() {
        $this->host = DB_HOST;
        $this->dbname = DB_NAME;
        $this->username = DB_USER;
        $this->password = DB_PASS;
        $this->charset = DB_CHARSET;
        
        $this->connect();
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function connect() {
        try {
            $dsn = "mysql:host={$this->host};dbname={$this->dbname};charset={$this->charset}";
            
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::ATTR_PERSISTENT         => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$this->charset}"
            ];

            $this->connection = new PDO($dsn, $this->username, $this->password, $options);
            
            // Set timezone to UTC
            $this->connection->exec("SET time_zone = '+00:00'");
            
            if (DEBUG_MODE) {
                error_log("Database connection established successfully");
            }
            
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Database connection failed',
                'code' => 'DB_CONNECTION_ERROR'
            ]);
            exit;
        }
    }

    public function getConnection() {
        // Check if connection is still alive
        try {
            $this->connection->query('SELECT 1');
        } catch (PDOException $e) {
            // Connection lost, reconnect
            $this->connect();
        }
        
        return $this->connection;
    }

    public function beginTransaction() {
        return $this->connection->beginTransaction();
    }

    public function commit() {
        return $this->connection->commit();
    }

    public function rollback() {
        return $this->connection->rollBack();
    }

    public function lastInsertId() {
        return $this->connection->lastInsertId();
    }

    public function prepare($query) {
        return $this->connection->prepare($query);
    }

    public function query($query) {
        return $this->connection->query($query);
    }

    public function exec($query) {
        return $this->connection->exec($query);
    }

    // Helper method for safe queries
    public function safeQuery($query, $params = []) {
        try {
            $stmt = $this->connection->prepare($query);
            $stmt->execute($params);
            return $stmt;
        } catch (PDOException $e) {
            error_log("Query failed: " . $e->getMessage());
            error_log("Query: " . $query);
            error_log("Params: " . json_encode($params));
            throw $e;
        }
    }

    // Helper method to check if table exists
    public function tableExists($tableName) {
        try {
            $stmt = $this->connection->prepare(
                "SELECT 1 FROM information_schema.tables 
                 WHERE table_schema = ? AND table_name = ? LIMIT 1"
            );
            $stmt->execute([$this->dbname, $tableName]);
            return $stmt->rowCount() > 0;
        } catch (PDOException $e) {
            return false;
        }
    }

    // Helper method for database health check
    public function healthCheck() {
        try {
            $stmt = $this->connection->query("SELECT 1 as status");
            $result = $stmt->fetch();
            
            return [
                'status' => 'healthy',
                'connection' => 'active',
                'database' => $this->dbname,
                'timestamp' => date('Y-m-d H:i:s'),
                'version' => $this->connection->getAttribute(PDO::ATTR_SERVER_VERSION)
            ];
        } catch (PDOException $e) {
            return [
                'status' => 'unhealthy',
                'error' => $e->getMessage(),
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }
    }

    // Get database statistics
    public function getStats() {
        try {
            $stats = [];
            
            // Get table statistics
            $stmt = $this->connection->query(
                "SELECT 
                    table_name,
                    table_rows,
                    ROUND(((data_length + index_length) / 1024 / 1024), 2) as size_mb
                 FROM information_schema.tables 
                 WHERE table_schema = '{$this->dbname}'"
            );
            
            $stats['tables'] = $stmt->fetchAll();
            
            // Get total database size
            $stmt = $this->connection->query(
                "SELECT 
                    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as total_size_mb
                 FROM information_schema.tables 
                 WHERE table_schema = '{$this->dbname}'"
            );
            
            $result = $stmt->fetch();
            $stats['total_size_mb'] = $result['total_size_mb'] ?? 0;
            
            return $stats;
        } catch (PDOException $e) {
            error_log("Failed to get database stats: " . $e->getMessage());
            return null;
        }
    }

    // Cleanup methods
    public function cleanExpiredSessions() {
        try {
            $stmt = $this->connection->prepare(
                "UPDATE user_sessions 
                 SET is_active = FALSE 
                 WHERE expires_at < NOW() AND is_active = TRUE"
            );
            $stmt->execute();
            
            $stmt = $this->connection->prepare(
                "DELETE FROM user_sessions 
                 WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 DAY)"
            );
            $stmt->execute();
            
            return $stmt->rowCount();
        } catch (PDOException $e) {
            error_log("Failed to clean expired sessions: " . $e->getMessage());
            return false;
        }
    }

    public function cleanExpiredMessages() {
        try {
            $stmt = $this->connection->prepare(
                "UPDATE messages 
                 SET is_deleted = TRUE, deleted_at = NOW()
                 WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_deleted = FALSE"
            );
            $stmt->execute();
            
            return $stmt->rowCount();
        } catch (PDOException $e) {
            error_log("Failed to clean expired messages: " . $e->getMessage());
            return false;
        }
    }

    // Prevent cloning and unserialization
    private function __clone() {}
    public function __wakeup() {}
}

// Global function for easy access
function getDB() {
    return Database::getInstance();
}

// Initialize database connection
try {
    Database::getInstance();
} catch (Exception $e) {
    error_log("Failed to initialize database: " . $e->getMessage());
    
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => 'Database initialization failed',
            'code' => 'DB_INIT_ERROR'
        ]);
    }
    exit;
}
?>
