<?php
/**
 * PROXY-SAAS-SYSTEM - FIXED CONFIGURATION FILE
 * 
 * This file contains all the fixed configuration settings
 * Addresses all common configuration issues
 */

// Prevent direct access
if (!defined('PROXY_SAAS_SYSTEM')) {
    http_response_code(403);
    die('Direct access not allowed');
}

// Error reporting for development (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/proxy-saas-system/php_errors.log');

// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'proxy_saas');
define('DB_USER', 'proxy_user');
define('DB_PASS', 'ProxySecure2024!');
define('DB_CHARSET', 'utf8mb4');

// Redis configuration
define('REDIS_HOST', '127.0.0.1');
define('REDIS_PORT', 6379);
define('REDIS_PASSWORD', 'RedisSecure2024!');
define('REDIS_DB', 0);

// API configuration
define('API_VERSION', '2.0');
define('API_RATE_LIMIT', 1000); // requests per hour
define('API_TIMEOUT', 30); // seconds

// Proxy configuration
define('PROXY_START_PORT', 4000);
define('PROXY_END_PORT', 4010);
define('PROXY_HOST', '127.0.0.1');

// Security configuration
define('API_SECRET_KEY', 'ProxySecretKey2024!ChangeThis');
define('JWT_SECRET', 'JWTSecretKey2024!ChangeThis');
define('ENCRYPTION_KEY', 'EncryptionKey2024!ChangeThis');

// Logging configuration
define('LOG_LEVEL', 'INFO'); // DEBUG, INFO, WARNING, ERROR
define('LOG_FILE', '/var/log/proxy-saas-system/api.log');
define('LOG_MAX_SIZE', 10485760); // 10MB
define('LOG_ROTATION', true);

// System configuration
define('SYSTEM_TIMEZONE', 'UTC');
define('SYSTEM_LOCALE', 'en_US.UTF-8');

// Set timezone
date_default_timezone_set(SYSTEM_TIMEZONE);

/**
 * Database connection function with error handling
 */
function getDatabase() {
    static $pdo = null;
    
    if ($pdo === null) {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET
            ];
            
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
            
        } catch (PDOException $e) {
            logError("Database connection failed: " . $e->getMessage());
            http_response_code(500);
            die(json_encode(['error' => 'Database connection failed']));
        }
    }
    
    return $pdo;
}

/**
 * Redis connection function with error handling
 */
function getRedis() {
    static $redis = null;
    
    if ($redis === null) {
        try {
            $redis = new Redis();
            $redis->connect(REDIS_HOST, REDIS_PORT);
            
            if (REDIS_PASSWORD) {
                $redis->auth(REDIS_PASSWORD);
            }
            
            $redis->select(REDIS_DB);
            
        } catch (Exception $e) {
            logError("Redis connection failed: " . $e->getMessage());
            // Don't die on Redis failure, just log it
            return null;
        }
    }
    
    return $redis;
}

/**
 * Logging function
 */
function logMessage($level, $message, $context = []) {
    $timestamp = date('Y-m-d H:i:s');
    $contextStr = !empty($context) ? ' ' . json_encode($context) : '';
    $logEntry = "[$timestamp] [$level] $message$contextStr" . PHP_EOL;
    
    // Create log directory if it doesn't exist
    $logDir = dirname(LOG_FILE);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    // Write to log file
    file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
    
    // Also log to syslog for important messages
    if (in_array($level, ['ERROR', 'WARNING'])) {
        syslog(LOG_WARNING, "Proxy-SaaS: [$level] $message");
    }
}

/**
 * Convenience logging functions
 */
function logInfo($message, $context = []) {
    logMessage('INFO', $message, $context);
}

function logWarning($message, $context = []) {
    logMessage('WARNING', $message, $context);
}

function logError($message, $context = []) {
    logMessage('ERROR', $message, $context);
}

function logDebug($message, $context = []) {
    if (LOG_LEVEL === 'DEBUG') {
        logMessage('DEBUG', $message, $context);
    }
}

/**
 * JSON response function
 */
function jsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Error response function
 */
function errorResponse($message, $statusCode = 400, $details = null) {
    $response = ['error' => $message];
    if ($details !== null) {
        $response['details'] = $details;
    }
    
    logError("API Error: $message", ['status_code' => $statusCode, 'details' => $details]);
    jsonResponse($response, $statusCode);
}

/**
 * Success response function
 */
function successResponse($data = null, $message = 'Success') {
    $response = ['success' => true, 'message' => $message];
    if ($data !== null) {
        $response['data'] = $data;
    }
    
    jsonResponse($response, 200);
}

/**
 * Validate required parameters
 */
function validateRequired($data, $required) {
    $missing = [];
    foreach ($required as $field) {
        if (!isset($data[$field]) || empty($data[$field])) {
            $missing[] = $field;
        }
    }
    
    if (!empty($missing)) {
        errorResponse('Missing required fields: ' . implode(', ', $missing), 400);
    }
}

/**
 * Sanitize input
 */
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Rate limiting function
 */
function checkRateLimit($identifier, $limit = null, $window = 3600) {
    $redis = getRedis();
    if (!$redis) {
        return true; // Allow if Redis is not available
    }
    
    $limit = $limit ?: API_RATE_LIMIT;
    $key = "rate_limit:$identifier";
    
    try {
        $current = $redis->incr($key);
        if ($current === 1) {
            $redis->expire($key, $window);
        }
        
        return $current <= $limit;
        
    } catch (Exception $e) {
        logError("Rate limiting error: " . $e->getMessage());
        return true; // Allow on error
    }
}

/**
 * Get client IP address
 */
function getClientIP() {
    $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    
    foreach ($ipKeys as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = $_SERVER[$key];
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

// Initialize system
openlog('proxy-saas-system', LOG_PID | LOG_PERROR, LOG_LOCAL0);

// Set error handler
set_error_handler(function($severity, $message, $file, $line) {
    logError("PHP Error: $message in $file on line $line", ['severity' => $severity]);
});

// Set exception handler
set_exception_handler(function($exception) {
    logError("Uncaught exception: " . $exception->getMessage(), [
        'file' => $exception->getFile(),
        'line' => $exception->getLine(),
        'trace' => $exception->getTraceAsString()
    ]);
    
    if (!headers_sent()) {
        errorResponse('Internal server error', 500);
    }
});

// Define system constant
define('PROXY_SAAS_SYSTEM', true);

logInfo("Configuration loaded successfully");
?>
