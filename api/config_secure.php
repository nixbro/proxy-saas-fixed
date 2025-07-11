<?php
/**
 * ============================================================================
 * PROXY-SAAS-SYSTEM - SECURE API CONFIGURATION
 * ============================================================================
 * 
 * SECURITY FIXES APPLIED:
 * ✅ All credentials moved to environment variables
 * ✅ Input validation functions added
 * ✅ Secure database connection with proper options
 * ✅ Environment-based error reporting
 * ✅ CORS security improvements
 * ============================================================================
 */

// Prevent direct access
if (!defined('PROXY_SAAS_SYSTEM')) {
    http_response_code(403);
    die('Direct access not allowed');
}

// Load environment variables from .env file if it exists
if (file_exists(__DIR__ . '/../../.env')) {
    $lines = file(__DIR__ . '/../../.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '=') !== false && strpos($line, '#') !== 0) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value, " \t\n\r\0\x0B\"'");
            if (!getenv($key)) {
                putenv("$key=$value");
                $_ENV[$key] = $value;
            }
        }
    }
}

// Environment-based error reporting
$app_env = $_ENV['APP_ENV'] ?? getenv('APP_ENV') ?: 'development';
if ($app_env === 'production') {
    error_reporting(0);
    ini_set('display_errors', 0);
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/proxy-saas-system/php_errors.log');

// Database configuration - SECURE: Uses environment variables
define('DB_HOST', $_ENV['DB_HOST'] ?? getenv('DB_HOST') ?: 'localhost');
define('DB_NAME', $_ENV['DB_NAME'] ?? getenv('DB_NAME') ?: 'proxy_saas');
define('DB_USER', $_ENV['DB_USER'] ?? getenv('DB_USER') ?: 'proxy_user');
define('DB_PASS', $_ENV['DB_PASSWORD'] ?? getenv('DB_PASSWORD') ?: '');
define('DB_CHARSET', $_ENV['DB_CHARSET'] ?? getenv('DB_CHARSET') ?: 'utf8mb4');

// Validate required database credentials
if (empty(DB_PASS)) {
    error_log('SECURITY ERROR: Database password not set in environment variables');
    http_response_code(500);
    exit('Configuration error: Database credentials not properly configured');
}

// Redis configuration - SECURE: Uses environment variables
define('REDIS_HOST', $_ENV['REDIS_HOST'] ?? getenv('REDIS_HOST') ?: '127.0.0.1');
define('REDIS_PORT', $_ENV['REDIS_PORT'] ?? getenv('REDIS_PORT') ?: 6379);
define('REDIS_PASSWORD', $_ENV['REDIS_PASSWORD'] ?? getenv('REDIS_PASSWORD') ?: '');
define('REDIS_DB', $_ENV['REDIS_DATABASE'] ?? getenv('REDIS_DATABASE') ?: 0);

// API configuration
define('API_VERSION', '2.0');
define('API_RATE_LIMIT', 1000); // requests per hour (no limit on IP Management API per user preference)
define('API_TIMEOUT', 30); // seconds

// Proxy configuration
define('PROXY_START_PORT', $_ENV['PROXY_PORT_START'] ?? getenv('PROXY_PORT_START') ?: 4000);
define('PROXY_END_PORT', $_ENV['PROXY_PORT_END'] ?? getenv('PROXY_PORT_END') ?: 4010);
define('PROXY_HOST', '127.0.0.1'); // Always localhost for security

// Security configuration - SECURE: Uses environment variables
define('API_SECRET_KEY', $_ENV['API_SECRET_KEY'] ?? getenv('API_SECRET_KEY') ?: '');
define('JWT_SECRET', $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET') ?: '');
define('ENCRYPTION_KEY', $_ENV['ENCRYPTION_KEY'] ?? getenv('ENCRYPTION_KEY') ?: '');

// Validate required security keys
$required_keys = ['API_SECRET_KEY', 'JWT_SECRET', 'ENCRYPTION_KEY'];
foreach ($required_keys as $key) {
    if (empty(constant($key))) {
        error_log("SECURITY ERROR: $key not set in environment variables");
        http_response_code(500);
        exit('Configuration error: Security keys not properly configured');
    }
}

// CORS configuration - SECURE: Restricted origins
$allowed_origins = $_ENV['ALLOWED_ORIGINS'] ?? getenv('ALLOWED_ORIGINS') ?: '';
define('ALLOWED_ORIGINS', $allowed_origins ? explode(',', $allowed_origins) : ['https://localhost', 'https://127.0.0.1']);

/**
 * SECURITY FUNCTION: Set secure CORS headers
 */
function setSecureCorsHeaders() {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    
    if (in_array($origin, ALLOWED_ORIGINS)) {
        header("Access-Control-Allow-Origin: $origin");
    }
    
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400'); // 24 hours
}

/**
 * SECURITY FUNCTION: Validate and sanitize input
 */
function validateInput($input, $type = 'string', $max_length = 255) {
    if ($input === null || $input === '') {
        return '';
    }
    
    // Remove null bytes and control characters
    $input = str_replace(["\0", "\r"], '', $input);
    
    switch ($type) {
        case 'email':
            return filter_var($input, FILTER_VALIDATE_EMAIL) ?: '';
        case 'int':
            return filter_var($input, FILTER_VALIDATE_INT) ?: 0;
        case 'float':
            return filter_var($input, FILTER_VALIDATE_FLOAT) ?: 0.0;
        case 'ip':
            return filter_var($input, FILTER_VALIDATE_IP) ?: '';
        case 'url':
            return filter_var($input, FILTER_VALIDATE_URL) ?: '';
        case 'alphanumeric':
            return preg_replace('/[^a-zA-Z0-9]/', '', $input);
        case 'username':
            return preg_replace('/[^a-zA-Z0-9_-]/', '', substr($input, 0, $max_length));
        case 'api_key':
            return preg_replace('/[^a-zA-Z0-9]/', '', substr($input, 0, 64));
        default:
            // String sanitization
            $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
            return substr($input, 0, $max_length);
    }
}

/**
 * SECURITY FUNCTION: Get client IP with proxy support
 */
function getClientIp() {
    $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    
    foreach ($ip_keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ips = explode(',', $_SERVER[$key]);
            $ip = trim($ips[0]);
            
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

/**
 * SECURITY FUNCTION: Rate limiting check
 */
function checkRateLimit($identifier, $limit = 100, $window = 3600) {
    static $redis = null;
    
    if ($redis === null) {
        try {
            $redis = new Redis();
            $redis->connect(REDIS_HOST, REDIS_PORT);
            if (!empty(REDIS_PASSWORD)) {
                $redis->auth(REDIS_PASSWORD);
            }
            $redis->select(REDIS_DB);
        } catch (Exception $e) {
            error_log("Redis connection failed for rate limiting: " . $e->getMessage());
            return true; // Allow request if Redis is down
        }
    }
    
    $key = "rate_limit:$identifier";
    $current = $redis->incr($key);
    
    if ($current === 1) {
        $redis->expire($key, $window);
    }
    
    return $current <= $limit;
}

/**
 * Database connection function with security options
 */
function getDatabase() {
    static $pdo = null;
    
    if ($pdo === null) {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false, // Use real prepared statements
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET,
                PDO::ATTR_TIMEOUT => 5, // 5 second timeout
                PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true
            ];
            
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
            
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            http_response_code(500);
            exit(json_encode(['error' => 'Database connection failed']));
        }
    }
    
    return $pdo;
}

/**
 * Secure logging function
 */
function logSecurityEvent($event, $ip, $username = '', $details = []) {
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event' => $event,
        'ip' => $ip,
        'username' => $username,
        'details' => $details,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'request_uri' => $_SERVER['REQUEST_URI'] ?? ''
    ];
    
    error_log("SECURITY_EVENT: " . json_encode($log_data));
}

// Set timezone
date_default_timezone_set($_ENV['TIMEZONE'] ?? getenv('TIMEZONE') ?: 'UTC');
