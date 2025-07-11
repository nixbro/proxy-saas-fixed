<?php
/**
 * PROXY-SAAS-SYSTEM - FIXED PROXIES API
 * 
 * This file provides the main proxy list API with all fixes applied
 * Handles proxy status, health checks, and proxy information
 */

// Include configuration
require_once __DIR__ . '/config.php';

// Set content type
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

/**
 * Check if a proxy port is listening
 */
function isProxyListening($host, $port, $timeout = 2) {
    $connection = @fsockopen($host, $port, $errno, $errstr, $timeout);
    if ($connection) {
        fclose($connection);
        return true;
    }
    return false;
}

/**
 * Get proxy status from PID files
 */
function getProxyStatus($port) {
    $pidFile = "/opt/proxy-saas-system/pids/proxy_{$port}.pid";
    
    if (!file_exists($pidFile)) {
        return 'stopped';
    }
    
    $pid = trim(file_get_contents($pidFile));
    if (empty($pid)) {
        return 'stopped';
    }
    
    // Check if process is running
    if (!posix_kill($pid, 0)) {
        return 'dead';
    }
    
    // Check if port is listening
    if (isProxyListening(PROXY_HOST, $port)) {
        return 'running';
    }
    
    return 'starting';
}

/**
 * Test proxy functionality
 */
function testProxy($host, $port, $timeout = 5) {
    $testUrl = 'http://httpbin.org/ip';
    $proxyUrl = "http://{$host}:{$port}";
    
    $context = stream_context_create([
        'http' => [
            'proxy' => $proxyUrl,
            'request_fulluri' => true,
            'timeout' => $timeout,
            'method' => 'GET',
            'header' => "User-Agent: Proxy-SaaS-Test/1.0\r\n"
        ]
    ]);
    
    $startTime = microtime(true);
    $result = @file_get_contents($testUrl, false, $context);
    $responseTime = round((microtime(true) - $startTime) * 1000, 2);
    
    if ($result === false) {
        return [
            'working' => false,
            'response_time' => null,
            'error' => 'Connection failed'
        ];
    }
    
    $data = json_decode($result, true);
    if (!$data || !isset($data['origin'])) {
        return [
            'working' => false,
            'response_time' => $responseTime,
            'error' => 'Invalid response'
        ];
    }
    
    return [
        'working' => true,
        'response_time' => $responseTime,
        'origin_ip' => $data['origin'],
        'error' => null
    ];
}

/**
 * Get system statistics
 */
function getSystemStats() {
    $stats = [
        'total_proxies' => 0,
        'running_proxies' => 0,
        'working_proxies' => 0,
        'system_load' => null,
        'memory_usage' => null,
        'uptime' => null
    ];
    
    // Count proxies
    for ($port = PROXY_START_PORT; $port <= PROXY_END_PORT; $port++) {
        $stats['total_proxies']++;
        $status = getProxyStatus($port);
        if ($status === 'running') {
            $stats['running_proxies']++;
        }
    }
    
    // Get system load
    if (function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        $stats['system_load'] = round($load[0], 2);
    }
    
    // Get memory usage
    if (function_exists('memory_get_usage')) {
        $stats['memory_usage'] = [
            'used' => memory_get_usage(true),
            'peak' => memory_get_peak_usage(true)
        ];
    }
    
    // Get uptime
    if (file_exists('/proc/uptime')) {
        $uptime = file_get_contents('/proc/uptime');
        $stats['uptime'] = (int)floatval($uptime);
    }
    
    return $stats;
}

/**
 * Main API handler
 */
function handleRequest() {
    $method = $_SERVER['REQUEST_METHOD'];
    $path = $_SERVER['REQUEST_URI'];
    $clientIP = getClientIP();
    
    // Rate limiting
    if (!checkRateLimit($clientIP)) {
        errorResponse('Rate limit exceeded', 429);
    }
    
    logInfo("API request: $method $path from $clientIP");
    
    try {
        switch ($method) {
            case 'GET':
                handleGetRequest();
                break;
                
            case 'POST':
                handlePostRequest();
                break;
                
            default:
                errorResponse('Method not allowed', 405);
        }
        
    } catch (Exception $e) {
        logError("API error: " . $e->getMessage(), [
            'method' => $method,
            'path' => $path,
            'client_ip' => $clientIP
        ]);
        errorResponse('Internal server error', 500);
    }
}

/**
 * Handle GET requests
 */
function handleGetRequest() {
    $action = $_GET['action'] ?? 'list';
    
    switch ($action) {
        case 'list':
            getProxyList();
            break;
            
        case 'status':
            getProxyStatusList();
            break;
            
        case 'test':
            testProxyEndpoint();
            break;
            
        case 'stats':
            getSystemStatsEndpoint();
            break;
            
        case 'health':
            getHealthCheck();
            break;
            
        default:
            errorResponse('Invalid action', 400);
    }
}

/**
 * Handle POST requests
 */
function handlePostRequest() {
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? $_POST['action'] ?? 'unknown';
    
    switch ($action) {
        case 'restart':
            restartProxy($input);
            break;
            
        case 'test_all':
            testAllProxies();
            break;
            
        default:
            errorResponse('Invalid action', 400);
    }
}

/**
 * Get proxy list
 */
function getProxyList() {
    $proxies = [];
    
    for ($port = PROXY_START_PORT; $port <= PROXY_END_PORT; $port++) {
        $proxies[] = [
            'id' => $port,
            'host' => PROXY_HOST,
            'port' => $port,
            'url' => "http://" . PROXY_HOST . ":" . $port,
            'status' => getProxyStatus($port),
            'type' => 'http',
            'auth_required' => false
        ];
    }
    
    successResponse([
        'proxies' => $proxies,
        'total' => count($proxies),
        'timestamp' => time()
    ]);
}

/**
 * Get detailed proxy status
 */
function getProxyStatusList() {
    $proxies = [];
    $runningCount = 0;
    
    for ($port = PROXY_START_PORT; $port <= PROXY_END_PORT; $port++) {
        $status = getProxyStatus($port);
        $isListening = isProxyListening(PROXY_HOST, $port, 1);
        
        if ($status === 'running') {
            $runningCount++;
        }
        
        $proxies[] = [
            'port' => $port,
            'status' => $status,
            'listening' => $isListening,
            'url' => "http://" . PROXY_HOST . ":" . $port,
            'last_check' => time()
        ];
    }
    
    successResponse([
        'proxies' => $proxies,
        'summary' => [
            'total' => count($proxies),
            'running' => $runningCount,
            'stopped' => count($proxies) - $runningCount
        ],
        'timestamp' => time()
    ]);
}

/**
 * Test specific proxy
 */
function testProxyEndpoint() {
    $port = (int)($_GET['port'] ?? 0);
    
    if ($port < PROXY_START_PORT || $port > PROXY_END_PORT) {
        errorResponse('Invalid port number', 400);
    }
    
    $result = testProxy(PROXY_HOST, $port);
    $result['port'] = $port;
    $result['timestamp'] = time();
    
    successResponse($result);
}

/**
 * Get system statistics
 */
function getSystemStatsEndpoint() {
    $stats = getSystemStats();
    $stats['timestamp'] = time();
    $stats['version'] = API_VERSION;
    
    successResponse($stats);
}

/**
 * Health check endpoint
 */
function getHealthCheck() {
    $health = [
        'status' => 'healthy',
        'timestamp' => time(),
        'version' => API_VERSION,
        'checks' => []
    ];
    
    // Check database
    try {
        $db = getDatabase();
        $db->query('SELECT 1');
        $health['checks']['database'] = 'ok';
    } catch (Exception $e) {
        $health['checks']['database'] = 'error';
        $health['status'] = 'unhealthy';
    }
    
    // Check Redis
    try {
        $redis = getRedis();
        if ($redis && $redis->ping()) {
            $health['checks']['redis'] = 'ok';
        } else {
            $health['checks']['redis'] = 'warning';
        }
    } catch (Exception $e) {
        $health['checks']['redis'] = 'error';
    }
    
    // Check proxy manager
    $runningProxies = 0;
    for ($port = PROXY_START_PORT; $port <= PROXY_END_PORT; $port++) {
        if (getProxyStatus($port) === 'running') {
            $runningProxies++;
        }
    }
    
    if ($runningProxies > 0) {
        $health['checks']['proxies'] = 'ok';
    } else {
        $health['checks']['proxies'] = 'error';
        $health['status'] = 'unhealthy';
    }
    
    $statusCode = ($health['status'] === 'healthy') ? 200 : 503;
    jsonResponse($health, $statusCode);
}

/**
 * Test all proxies
 */
function testAllProxies() {
    $results = [];
    
    for ($port = PROXY_START_PORT; $port <= PROXY_END_PORT; $port++) {
        if (getProxyStatus($port) === 'running') {
            $results[$port] = testProxy(PROXY_HOST, $port, 3);
        } else {
            $results[$port] = [
                'working' => false,
                'response_time' => null,
                'error' => 'Proxy not running'
            ];
        }
    }
    
    successResponse([
        'results' => $results,
        'timestamp' => time()
    ]);
}

// Handle the request
handleRequest();
?>
