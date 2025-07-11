<?php
/**
 * PROXY-SAAS-SYSTEM - FIXED INTERNAL AUTHENTICATION API
 * 
 * This file handles internal authentication for GoProxy
 * Used by GoProxy for user authentication and authorization
 */

// Include configuration
require_once dirname(__DIR__) . '/config.php';

// Set content type
header('Content-Type: application/json');

/**
 * Authenticate user based on different methods
 */
function authenticateUser($username, $password, $clientIP, $targetHost, $targetPort) {
    $db = getDatabase();
    
    try {
        // First, try API key authentication
        if (empty($password)) {
            $stmt = $db->prepare("
                SELECT id, username, plan, status, max_threads, current_bandwidth_gb, max_bandwidth_gb, strikes, strike_timeout
                FROM users 
                WHERE api_key = ? AND status = 'active'
            ");
            $stmt->execute([$username]);
        } else {
            // Username/password authentication
            $stmt = $db->prepare("
                SELECT id, username, password_hash, plan, status, max_threads, current_bandwidth_gb, max_bandwidth_gb, strikes, strike_timeout
                FROM users 
                WHERE username = ? AND status = 'active'
            ");
            $stmt->execute([$username]);
        }
        
        $user = $stmt->fetch();
        
        if (!$user) {
            logAuthAttempt(null, $username, $clientIP, $targetHost, $targetPort, 'password', 'failed', 'User not found');
            return ['success' => false, 'reason' => 'Invalid credentials'];
        }
        
        // Check password if provided
        if (!empty($password) && !password_verify($password, $user['password_hash'])) {
            logAuthAttempt($user['id'], $username, $clientIP, $targetHost, $targetPort, 'password', 'failed', 'Invalid password');
            return ['success' => false, 'reason' => 'Invalid credentials'];
        }
        
        // Check if user is in strike timeout
        if ($user['strikes'] >= 3 && $user['strike_timeout'] && strtotime($user['strike_timeout']) > time()) {
            logAuthAttempt($user['id'], $username, $clientIP, $targetHost, $targetPort, 'password', 'blocked', 'User in timeout');
            return ['success' => false, 'reason' => 'Account temporarily suspended'];
        }
        
        // Check bandwidth quota
        if ($user['current_bandwidth_gb'] >= $user['max_bandwidth_gb']) {
            logAuthAttempt($user['id'], $username, $clientIP, $targetHost, $targetPort, 'password', 'blocked', 'Bandwidth exceeded');
            return ['success' => false, 'reason' => 'Bandwidth quota exceeded'];
        }
        
        // Check IP whitelist if configured
        if (!checkIPWhitelist($user['id'], $clientIP)) {
            logAuthAttempt($user['id'], $username, $clientIP, $targetHost, $targetPort, 'ip_whitelist', 'failed', 'IP not whitelisted');
            return ['success' => false, 'reason' => 'IP address not authorized'];
        }
        
        // Authentication successful
        logAuthAttempt($user['id'], $username, $clientIP, $targetHost, $targetPort, 'password', 'success', null);
        
        // Reset strikes on successful auth
        if ($user['strikes'] > 0) {
            $stmt = $db->prepare("UPDATE users SET strikes = 0, strike_timeout = NULL WHERE id = ?");
            $stmt->execute([$user['id']]);
        }
        
        return [
            'success' => true,
            'user_id' => $user['id'],
            'username' => $user['username'],
            'plan' => $user['plan'],
            'max_threads' => $user['max_threads']
        ];
        
    } catch (Exception $e) {
        logError("Authentication error: " . $e->getMessage());
        return ['success' => false, 'reason' => 'Authentication service error'];
    }
}

/**
 * Check IP whitelist for user
 */
function checkIPWhitelist($userId, $clientIP) {
    $db = getDatabase();
    
    try {
        $stmt = $db->prepare("
            SELECT COUNT(*) as count 
            FROM user_ips 
            WHERE user_id = ? AND ip_address = ? AND is_active = 1
        ");
        $stmt->execute([$userId, $clientIP]);
        $result = $stmt->fetch();
        
        // If no IP restrictions are set, allow all IPs
        $stmt = $db->prepare("SELECT COUNT(*) as total FROM user_ips WHERE user_id = ? AND is_active = 1");
        $stmt->execute([$userId]);
        $total = $stmt->fetch();
        
        if ($total['total'] == 0) {
            return true; // No IP restrictions
        }
        
        return $result['count'] > 0;
        
    } catch (Exception $e) {
        logError("IP whitelist check error: " . $e->getMessage());
        return true; // Allow on error
    }
}

/**
 * Log authentication attempt
 */
function logAuthAttempt($userId, $username, $clientIP, $targetHost, $targetPort, $authMethod, $result, $reason) {
    $db = getDatabase();
    
    try {
        $stmt = $db->prepare("
            INSERT INTO auth_logs (user_id, username, client_ip, target_host, target_port, auth_method, auth_result, failure_reason, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'GoProxy';
        
        $stmt->execute([
            $userId,
            $username,
            $clientIP,
            $targetHost,
            $targetPort,
            $authMethod,
            $result,
            $reason,
            $userAgent
        ]);
        
    } catch (Exception $e) {
        logError("Failed to log auth attempt: " . $e->getMessage());
    }
}

/**
 * Handle rate limiting
 */
function checkRateLimit($userId, $clientIP) {
    $redis = getRedis();
    if (!$redis) {
        return true; // Allow if Redis is not available
    }
    
    $key = "auth_rate_limit:$userId:$clientIP";
    $limit = 60; // 60 attempts per hour
    $window = 3600; // 1 hour
    
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
 * Main authentication handler
 */
function handleAuthRequest() {
    $method = $_SERVER['REQUEST_METHOD'];
    
    if ($method !== 'GET') {
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        return;
    }
    
    // Get parameters from GoProxy
    $username = $_GET['user'] ?? '';
    $password = $_GET['pass'] ?? '';
    $clientIP = $_GET['client_addr'] ?? getClientIP();
    $targetHost = $_GET['target'] ?? '';
    $targetPort = (int)($_GET['target_port'] ?? 0);
    $service = $_GET['service'] ?? 'http';
    
    logInfo("Auth request", [
        'username' => $username,
        'client_ip' => $clientIP,
        'target' => "$targetHost:$targetPort",
        'service' => $service
    ]);
    
    // Validate required parameters
    if (empty($username)) {
        http_response_code(400);
        echo json_encode(['error' => 'Username required']);
        return;
    }
    
    // Check rate limiting
    if (!checkRateLimit($username, $clientIP)) {
        http_response_code(429);
        echo json_encode(['error' => 'Rate limit exceeded']);
        return;
    }
    
    // Authenticate user
    $authResult = authenticateUser($username, $password, $clientIP, $targetHost, $targetPort);
    
    if ($authResult['success']) {
        // Return success response for GoProxy
        http_response_code(204); // No Content - GoProxy expects this for success
        
        // Set headers for GoProxy configuration
        header("userconns: " . $authResult['max_threads']);
        header("ipconns: 10");
        header("userrate: 1000");
        header("iprate: 100");
        
        logInfo("Authentication successful", [
            'username' => $authResult['username'],
            'user_id' => $authResult['user_id'],
            'client_ip' => $clientIP
        ]);
        
    } else {
        // Return error response
        http_response_code(403);
        echo json_encode(['error' => $authResult['reason']]);
        
        logWarning("Authentication failed", [
            'username' => $username,
            'client_ip' => $clientIP,
            'reason' => $authResult['reason']
        ]);
    }
}

/**
 * Health check endpoint
 */
function handleHealthCheck() {
    $health = [
        'status' => 'healthy',
        'timestamp' => time(),
        'service' => 'auth'
    ];
    
    // Check database
    try {
        $db = getDatabase();
        $db->query('SELECT 1');
        $health['database'] = 'ok';
    } catch (Exception $e) {
        $health['database'] = 'error';
        $health['status'] = 'unhealthy';
    }
    
    // Check Redis
    try {
        $redis = getRedis();
        if ($redis && $redis->ping()) {
            $health['redis'] = 'ok';
        } else {
            $health['redis'] = 'warning';
        }
    } catch (Exception $e) {
        $health['redis'] = 'error';
    }
    
    $statusCode = ($health['status'] === 'healthy') ? 200 : 503;
    http_response_code($statusCode);
    echo json_encode($health);
}

// Handle the request
$action = $_GET['action'] ?? 'auth';

switch ($action) {
    case 'auth':
        handleAuthRequest();
        break;
        
    case 'health':
        handleHealthCheck();
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
}
?>
