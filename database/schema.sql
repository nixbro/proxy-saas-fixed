-- ============================================================================
-- PROXY-SAAS-SYSTEM - FIXED DATABASE SCHEMA
-- ============================================================================
-- 
-- Complete database schema with all fixes applied
-- Addresses foreign key issues, data types, and constraints
-- ============================================================================

-- Set SQL mode and character set
SET SQL_MODE = 'NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO';
SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS proxy_saas 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE proxy_saas;

-- Drop existing tables in correct order (reverse dependency order)
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS traffic_logs;
DROP TABLE IF EXISTS auth_logs;
DROP TABLE IF EXISTS user_ips;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS proxy_instances;
DROP TABLE IF EXISTS system_config;

-- ============================================================================
-- SYSTEM CONFIGURATION TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_config_key (config_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- PROXY INSTANCES TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS proxy_instances (
    id INT AUTO_INCREMENT PRIMARY KEY,
    port INT NOT NULL UNIQUE,
    host VARCHAR(255) NOT NULL DEFAULT '127.0.0.1',
    status ENUM('running', 'stopped', 'error', 'starting') DEFAULT 'stopped',
    pid INT NULL,
    upstream_proxy VARCHAR(500) NULL,
    auth_method ENUM('none', 'user_pass', 'ip_whitelist') DEFAULT 'none',
    max_connections INT DEFAULT 100,
    current_connections INT DEFAULT 0,
    bytes_transferred BIGINT DEFAULT 0,
    last_activity TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_port (port),
    INDEX idx_status (status),
    INDEX idx_last_activity (last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) NOT NULL UNIQUE,
    plan ENUM('free', 'basic', 'pro', 'enterprise') DEFAULT 'free',
    status ENUM('active', 'suspended', 'banned') DEFAULT 'active',
    
    -- Quota settings
    max_threads INT DEFAULT 10,
    max_bandwidth_gb DECIMAL(10,2) DEFAULT 1.00,
    current_bandwidth_gb DECIMAL(10,2) DEFAULT 0.00,
    
    -- Rate limiting
    requests_per_hour INT DEFAULT 100,
    current_requests INT DEFAULT 0,
    rate_limit_reset TIMESTAMP NULL,
    
    -- Strike system
    strikes INT DEFAULT 0,
    strike_timeout TIMESTAMP NULL,
    
    -- Timestamps
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_api_key (api_key),
    INDEX idx_plan (plan),
    INDEX idx_status (status),
    INDEX idx_last_login (last_login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- USER IP WHITELIST TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    description VARCHAR(255) NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_ip (user_id, ip_address),
    INDEX idx_user_id (user_id),
    INDEX idx_ip_address (ip_address),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- AUTHENTICATION LOGS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    username VARCHAR(50) NULL,
    client_ip VARCHAR(45) NOT NULL,
    target_host VARCHAR(255) NULL,
    target_port INT NULL,
    auth_method ENUM('password', 'api_key', 'ip_whitelist') NOT NULL,
    auth_result ENUM('success', 'failed', 'blocked') NOT NULL,
    failure_reason VARCHAR(255) NULL,
    user_agent TEXT NULL,
    proxy_port INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_client_ip (client_ip),
    INDEX idx_auth_result (auth_result),
    INDEX idx_created_at (created_at),
    INDEX idx_proxy_port (proxy_port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TRAFFIC LOGS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS traffic_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    client_ip VARCHAR(45) NOT NULL,
    proxy_port INT NOT NULL,
    target_host VARCHAR(255) NULL,
    target_port INT NULL,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    total_bytes BIGINT GENERATED ALWAYS AS (bytes_sent + bytes_received) STORED,
    connection_duration INT DEFAULT 0,
    session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_end TIMESTAMP NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_client_ip (client_ip),
    INDEX idx_proxy_port (proxy_port),
    INDEX idx_session_start (session_start),
    INDEX idx_total_bytes (total_bytes)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- USER SESSIONS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(128) NOT NULL UNIQUE,
    client_ip VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_session_token (session_token),
    INDEX idx_expires_at (expires_at),
    INDEX idx_is_active (is_active),
    INDEX idx_last_activity (last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- INSERT DEFAULT DATA
-- ============================================================================

-- Insert system configuration
INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES
('system_version', '2.0.0', 'System version'),
('maintenance_mode', 'false', 'Maintenance mode flag'),
('max_users', '1000', 'Maximum number of users'),
('default_user_plan', 'free', 'Default plan for new users'),
('rate_limit_enabled', 'true', 'Enable rate limiting'),
('logging_enabled', 'true', 'Enable detailed logging'),
('strike_threshold', '3', 'Number of strikes before timeout'),
('strike_timeout_hours', '1', 'Hours to timeout after strikes'),
('bandwidth_check_interval', '300', 'Bandwidth check interval in seconds'),
('cleanup_logs_days', '30', 'Days to keep logs before cleanup');

-- Insert default proxy instances
INSERT IGNORE INTO proxy_instances (port, host, status, max_connections) VALUES
(4000, '127.0.0.1', 'stopped', 100),
(4001, '127.0.0.1', 'stopped', 100),
(4002, '127.0.0.1', 'stopped', 100),
(4003, '127.0.0.1', 'stopped', 100),
(4004, '127.0.0.1', 'stopped', 100),
(4005, '127.0.0.1', 'stopped', 100),
(4006, '127.0.0.1', 'stopped', 100),
(4007, '127.0.0.1', 'stopped', 100),
(4008, '127.0.0.1', 'stopped', 100),
(4009, '127.0.0.1', 'stopped', 100),
(4010, '127.0.0.1', 'stopped', 100);

-- Insert demo user (password: demo123)
INSERT IGNORE INTO users (
    username, 
    email, 
    password_hash, 
    api_key, 
    plan, 
    max_threads, 
    max_bandwidth_gb,
    requests_per_hour
) VALUES (
    'demo', 
    'demo@example.com', 
    '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 
    'demo_api_key_12345678901234567890123456789012',
    'basic',
    50,
    10.00,
    1000
);

-- ============================================================================
-- CREATE STORED PROCEDURES
-- ============================================================================

DELIMITER //

-- Procedure to cleanup old logs
CREATE PROCEDURE IF NOT EXISTS CleanupOldLogs()
BEGIN
    DECLARE cleanup_days INT DEFAULT 30;
    
    -- Get cleanup days from config
    SELECT CAST(config_value AS UNSIGNED) INTO cleanup_days 
    FROM system_config 
    WHERE config_key = 'cleanup_logs_days' 
    LIMIT 1;
    
    -- Delete old auth logs
    DELETE FROM auth_logs 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL cleanup_days DAY);
    
    -- Delete old traffic logs
    DELETE FROM traffic_logs 
    WHERE session_start < DATE_SUB(NOW(), INTERVAL cleanup_days DAY);
    
    -- Delete expired sessions
    DELETE FROM user_sessions 
    WHERE expires_at < NOW() OR last_activity < DATE_SUB(NOW(), INTERVAL 7 DAY);
    
END //

-- Procedure to reset user bandwidth
CREATE PROCEDURE IF NOT EXISTS ResetUserBandwidth()
BEGIN
    UPDATE users 
    SET current_bandwidth_gb = 0.00,
        current_requests = 0,
        rate_limit_reset = NOW()
    WHERE DATE(rate_limit_reset) < CURDATE() OR rate_limit_reset IS NULL;
END //

DELIMITER ;

-- ============================================================================
-- CREATE EVENTS FOR MAINTENANCE
-- ============================================================================

-- Enable event scheduler
SET GLOBAL event_scheduler = ON;

-- Event to cleanup old logs daily
DROP EVENT IF EXISTS cleanup_logs_daily;
CREATE EVENT IF NOT EXISTS cleanup_logs_daily
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL CleanupOldLogs();

-- Event to reset bandwidth monthly
DROP EVENT IF EXISTS reset_bandwidth_monthly;
CREATE EVENT IF NOT EXISTS reset_bandwidth_monthly
ON SCHEDULE EVERY 1 MONTH
STARTS CURRENT_TIMESTAMP
DO CALL ResetUserBandwidth();

-- ============================================================================
-- FINAL OPTIMIZATIONS
-- ============================================================================

-- Optimize tables
OPTIMIZE TABLE system_config, proxy_instances, users, user_ips, auth_logs, traffic_logs, user_sessions;

-- Update table statistics
ANALYZE TABLE system_config, proxy_instances, users, user_ips, auth_logs, traffic_logs, user_sessions;

-- Show completion message
SELECT 'Database schema created successfully!' as message;
