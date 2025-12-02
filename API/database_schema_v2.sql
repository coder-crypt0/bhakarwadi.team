-- Enhanced Tornado Messenger Database Schema
-- Supports persistent sessions, global chat, user blocking, etc.
-- Version 2.0.0 - Group 18

-- Update users table with enhanced features
ALTER TABLE `users` 
ADD COLUMN `email` VARCHAR(255) UNIQUE DEFAULT NULL AFTER `username`,
ADD COLUMN `email_verified` BOOLEAN DEFAULT FALSE AFTER `email`,
ADD COLUMN `last_seen` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER `updated_at`,
ADD COLUMN `is_online` BOOLEAN DEFAULT FALSE AFTER `last_seen`,
ADD COLUMN `preferred_language` VARCHAR(10) DEFAULT 'en' AFTER `is_online`,
ADD COLUMN `blocked_users` JSON DEFAULT NULL AFTER `preferred_language`;

-- Enhanced user_sessions table for persistent login
CREATE TABLE IF NOT EXISTS `user_sessions` (
    `session_id` VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    `user_id` VARCHAR(36) NOT NULL,
    `session_token` VARCHAR(255) UNIQUE NOT NULL,
    `device_info` JSON DEFAULT NULL,
    `ip_address` VARCHAR(45) DEFAULT NULL,
    `remember_me` BOOLEAN DEFAULT FALSE,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME NOT NULL,
    `last_activity` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `is_active` BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
    INDEX `idx_session_token` (`session_token`),
    INDEX `idx_user_sessions` (`user_id`, `is_active`),
    INDEX `idx_session_expiry` (`expires_at`)
);

-- Global chat rooms
CREATE TABLE IF NOT EXISTS `chat_rooms` (
    `room_id` VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    `room_name` VARCHAR(100) NOT NULL,
    `room_type` ENUM('global', 'private', 'group') DEFAULT 'global',
    `description` TEXT DEFAULT NULL,
    `created_by` VARCHAR(36) NOT NULL,
    `max_members` INT DEFAULT 1000,
    `is_active` BOOLEAN DEFAULT TRUE,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`created_by`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
    INDEX `idx_room_type` (`room_type`, `is_active`)
);

-- Insert default global chat room
INSERT IGNORE INTO `chat_rooms` (`room_id`, `room_name`, `room_type`, `description`, `created_by`) 
VALUES ('global-main', 'Global Chat', 'global', 'Main global chat room for all users', 
    (SELECT user_id FROM users WHERE username = 'system' LIMIT 1));

-- Room memberships
CREATE TABLE IF NOT EXISTS `room_members` (
    `membership_id` VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    `room_id` VARCHAR(36) NOT NULL,
    `user_id` VARCHAR(36) NOT NULL,
    `role` ENUM('member', 'moderator', 'admin') DEFAULT 'member',
    `joined_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `last_read_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `is_active` BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (`room_id`) REFERENCES `chat_rooms`(`room_id`) ON DELETE CASCADE,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
    UNIQUE KEY `unique_room_user` (`room_id`, `user_id`),
    INDEX `idx_user_rooms` (`user_id`, `is_active`)
);

-- Enhanced messages table
ALTER TABLE `messages` 
ADD COLUMN `room_id` VARCHAR(36) DEFAULT NULL AFTER `message_id`,
ADD COLUMN `message_type` ENUM('text', 'file', 'image', 'system', 'global') DEFAULT 'text' AFTER `content`,
ADD COLUMN `parent_message_id` VARCHAR(36) DEFAULT NULL AFTER `message_type`,
ADD COLUMN `edited_at` DATETIME DEFAULT NULL AFTER `created_at`,
ADD COLUMN `is_global` BOOLEAN DEFAULT FALSE AFTER `is_encrypted`,
ADD FOREIGN KEY (`room_id`) REFERENCES `chat_rooms`(`room_id`) ON DELETE SET NULL,
ADD FOREIGN KEY (`parent_message_id`) REFERENCES `messages`(`message_id`) ON DELETE SET NULL,
ADD INDEX `idx_room_messages` (`room_id`, `created_at`),
ADD INDEX `idx_global_messages` (`is_global`, `created_at`);

-- User blocking system
CREATE TABLE IF NOT EXISTS `user_blocks` (
    `block_id` VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    `blocker_id` VARCHAR(36) NOT NULL,
    `blocked_id` VARCHAR(36) NOT NULL,
    `reason` TEXT DEFAULT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`blocker_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
    FOREIGN KEY (`blocked_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
    UNIQUE KEY `unique_block` (`blocker_id`, `blocked_id`),
    INDEX `idx_blocker_blocks` (`blocker_id`),
    INDEX `idx_blocked_users` (`blocked_id`)
);

-- Message read receipts
CREATE TABLE IF NOT EXISTS `message_receipts` (
    `receipt_id` VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    `message_id` VARCHAR(36) NOT NULL,
    `user_id` VARCHAR(36) NOT NULL,
    `read_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`message_id`) REFERENCES `messages`(`message_id`) ON DELETE CASCADE,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
    UNIQUE KEY `unique_receipt` (`message_id`, `user_id`),
    INDEX `idx_user_receipts` (`user_id`, `read_at`)
);

-- Online users tracking
CREATE TABLE IF NOT EXISTS `user_presence` (
    `presence_id` VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    `user_id` VARCHAR(36) NOT NULL,
    `status` ENUM('online', 'away', 'busy', 'invisible', 'offline') DEFAULT 'offline',
    `last_activity` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `device_info` JSON DEFAULT NULL,
    `ip_address` VARCHAR(45) DEFAULT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
    UNIQUE KEY `unique_user_presence` (`user_id`),
    INDEX `idx_online_users` (`status`, `last_activity`)
);

-- API usage tracking for rate limiting
CREATE TABLE IF NOT EXISTS `api_rate_limits` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL,
    `endpoint` VARCHAR(100) NOT NULL,
    `request_count` INT DEFAULT 1,
    `window_start` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `last_request` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `unique_ip_endpoint` (`ip_address`, `endpoint`),
    INDEX `idx_rate_limit_window` (`window_start`)
);

-- System notifications
CREATE TABLE IF NOT EXISTS `notifications` (
    `notification_id` VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    `user_id` VARCHAR(36) NOT NULL,
    `type` ENUM('message', 'friend_request', 'system', 'security') DEFAULT 'message',
    `title` VARCHAR(255) NOT NULL,
    `content` TEXT DEFAULT NULL,
    `data` JSON DEFAULT NULL,
    `is_read` BOOLEAN DEFAULT FALSE,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME DEFAULT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE,
    INDEX `idx_user_notifications` (`user_id`, `is_read`, `created_at`)
);

-- Create stored procedures for common operations

DELIMITER //

-- Procedure to get online users
CREATE PROCEDURE GetOnlineUsers()
BEGIN
    SELECT u.user_id, u.username, u.display_name, u.status, p.last_activity
    FROM users u
    JOIN user_presence p ON u.user_id = p.user_id
    WHERE p.status IN ('online', 'away', 'busy') 
    AND p.last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
    ORDER BY p.last_activity DESC;
END //

-- Procedure to clean expired sessions
CREATE PROCEDURE CleanExpiredSessions()
BEGIN
    UPDATE user_sessions 
    SET is_active = FALSE 
    WHERE expires_at < NOW() AND is_active = TRUE;
    
    DELETE FROM user_sessions 
    WHERE expires_at < DATE_SUB(NOW(), INTERVAL 7 DAY);
END //

-- Procedure to update user presence
CREATE PROCEDURE UpdateUserPresence(
    IN p_user_id VARCHAR(36),
    IN p_status VARCHAR(20),
    IN p_device_info JSON,
    IN p_ip_address VARCHAR(45)
)
BEGIN
    INSERT INTO user_presence (user_id, status, device_info, ip_address)
    VALUES (p_user_id, p_status, p_device_info, p_ip_address)
    ON DUPLICATE KEY UPDATE
        status = VALUES(status),
        last_activity = CURRENT_TIMESTAMP,
        device_info = VALUES(device_info),
        ip_address = VALUES(ip_address);
        
    UPDATE users SET is_online = (p_status != 'offline'), last_seen = NOW() 
    WHERE user_id = p_user_id;
END //

DELIMITER ;

-- Create views for common queries

-- View for user sessions with user info
CREATE OR REPLACE VIEW active_sessions AS
SELECT 
    s.session_id,
    s.session_token,
    s.user_id,
    u.username,
    u.display_name,
    s.created_at,
    s.expires_at,
    s.last_activity,
    s.remember_me,
    s.ip_address
FROM user_sessions s
JOIN users u ON s.user_id = u.user_id
WHERE s.is_active = TRUE AND s.expires_at > NOW();

-- View for global messages with user info
CREATE OR REPLACE VIEW global_messages AS
SELECT 
    m.message_id,
    m.content,
    m.message_type,
    m.created_at,
    m.edited_at,
    u.username as sender_username,
    u.display_name as sender_name,
    u.status as sender_status
FROM messages m
JOIN users u ON m.sender_id = u.user_id
WHERE m.is_global = TRUE OR m.room_id = 'global-main'
ORDER BY m.created_at DESC;

-- Add triggers for automatic operations

DELIMITER //

-- Trigger to automatically join users to global chat
CREATE TRIGGER after_user_insert
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    INSERT INTO room_members (room_id, user_id, role)
    VALUES ('global-main', NEW.user_id, 'member');
END //

-- Trigger to update last activity on message send
CREATE TRIGGER after_message_insert
AFTER INSERT ON messages
FOR EACH ROW
BEGIN
    CALL UpdateUserPresence(NEW.sender_id, 'online', NULL, NULL);
END //

DELIMITER ;
