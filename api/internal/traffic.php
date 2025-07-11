<?php
/**
 * PROXY-SAAS-SYSTEM - TRAFFIC MONITORING API
 * 
 * This file handles traffic reporting from GoProxy
 * Used by GoProxy for traffic monitoring and bandwidth tracking
 */

// Include configuration
require_once dirname(__DIR__) . '/config.php';

// Set content type
header('Content-Type: application/json');

/**
 * Log traffic data to database
 */
function logTrafficData($data) {
    $db = getDatabase();
    
    try {
        // Extract parameters from GoProxy traffic report
        $bytes = (int)($data['bytes'] ?? 0);
        $clientAddr = $data['client_addr'] ?? '';
        $serverAddr = $data['server_addr'] ?? '';
        $targetAddr = $data['target_addr'] ?? '';
        $username = $data['username'] ?? '';
        $outLocalAddr = $data['out_local_addr'] ?? '';
        $outRemoteAddr = $data['out_remote_addr'] ?? '';
        $upstream = $data['upstream'] ?? '';
        
        // Parse target address to get host and port
        $targetHost = '';
        $targetPort = 0;
        if (!empty($targetAddr)) {
            $parts = explode(':', $targetAddr);
            $targetHost = $parts[0] ?? '';
            $targetPort = (int)($parts[1] ?? 0);
        }
        
        // Parse server address to get proxy port
        $proxyPort = 0;
        if (!empty($serverAddr)) {
            $parts = explode(':', $serverAddr);
            $proxyPort = (int)($parts[1] ?? 0);
        }
        
        // Get user ID if username is provided
        $userId = null;
        if (!empty($username)) {
            $stmt = $db->prepare("SELECT id FROM users WHERE username = ? OR api_key = ?");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();
            if ($user) {
                $userId = $user['id'];
            }
        }
        
        // Insert traffic log
        $stmt = $db->prepare("
            INSERT INTO traffic_logs (
                user_id, client_ip, proxy_port, target_host, target_port,
                bytes_sent, bytes_received, session_start, session_end
            ) VALUES (?, ?, ?, ?, ?, ?, 0, NOW(), NOW())
        ");
        
        $stmt->execute([
            $userId,
            $clientAddr,
            $proxyPort,
            $targetHost,
            $targetPort,
            $bytes
        ]);
        
        // Update user bandwidth if user is identified
        if ($userId) {
            $bytesGB = $bytes / (1024 * 1024 * 1024);
            $stmt = $db->prepare("
                UPDATE users 
                SET current_bandwidth_gb = current_bandwidth_gb + ? 
                WHERE id = ?
            ");
            $stmt->execute([$bytesGB, $userId]);
        }
        
        // Update proxy instance statistics
        if ($proxyPort > 0) {
            $stmt = $db->prepare("
                UPDATE proxy_instances 
                SET bytes_transferred = bytes_transferred + ?, last_activity = NOW() 
                WHERE port = ?
            ");
            $stmt->execute([$bytes, $proxyPort]);
        }
        
        logInfo("Traffic logged", [
            'user_id' => $userId,
            'username' => $username,
            'client_ip' => $clientAddr,
            'proxy_port' => $proxyPort,
            'bytes' => $bytes,
            'target' => $targetAddr
        ]);
        
        return true;
        
    } catch (Exception $e) {
        logError("Traffic logging error: " . $e->getMessage(), [
            'data' => $data
        ]);
        return false;
    }
}

/**
 * Get traffic statistics
 */
function getTrafficStats($timeframe = '24h') {
    $db = getDatabase();
    
    try {
        $interval = match($timeframe) {
            '1h' => 'INTERVAL 1 HOUR',
            '24h' => 'INTERVAL 24 HOUR',
            '7d' => 'INTERVAL 7 DAY',
            '30d' => 'INTERVAL 30 DAY',
            default => 'INTERVAL 24 HOUR'
        };
        
        // Total traffic
        $stmt = $db->prepare("
            SELECT 
                COUNT(*) as total_sessions,
                SUM(total_bytes) as total_bytes,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT proxy_port) as active_ports
            FROM traffic_logs 
            WHERE session_start >= DATE_SUB(NOW(), $interval)
        ");
        $stmt->execute();
        $totals = $stmt->fetch();
        
        // Top users by traffic
        $stmt = $db->prepare("
            SELECT 
                u.username,
                u.id as user_id,
                COUNT(tl.id) as sessions,
                SUM(tl.total_bytes) as total_bytes
            FROM traffic_logs tl
            LEFT JOIN users u ON tl.user_id = u.id
            WHERE tl.session_start >= DATE_SUB(NOW(), $interval)
            GROUP BY tl.user_id
            ORDER BY total_bytes DESC
            LIMIT 10
        ");
        $stmt->execute();
        $topUsers = $stmt->fetchAll();
        
        // Traffic by proxy port
        $stmt = $db->prepare("
            SELECT 
                proxy_port,
                COUNT(*) as sessions,
                SUM(total_bytes) as total_bytes
            FROM traffic_logs 
            WHERE session_start >= DATE_SUB(NOW(), $interval)
            GROUP BY proxy_port
            ORDER BY total_bytes DESC
            LIMIT 20
        ");
        $stmt->execute();
        $portStats = $stmt->fetchAll();
        
        return [
            'timeframe' => $timeframe,
            'totals' => $totals,
            'top_users' => $topUsers,
            'port_stats' => $portStats,
            'timestamp' => time()
        ];
        
    } catch (Exception $e) {
        logError("Traffic stats error: " . $e->getMessage());
        return null;
    }
}

/**
 * Handle traffic requests
 */
function handleTrafficRequest() {
    $method = $_SERVER['REQUEST_METHOD'];
    
    try {
        switch ($method) {
            case 'GET':
                // GoProxy traffic report or stats request
                $action = $_GET['action'] ?? 'report';
                
                if ($action === 'stats') {
                    $timeframe = $_GET['timeframe'] ?? '24h';
                    $stats = getTrafficStats($timeframe);
                    
                    if ($stats) {
                        jsonResponse($stats);
                    } else {
                        errorResponse('Failed to get traffic statistics', 500);
                    }
                } else {
                    // Handle GoProxy traffic report
                    $data = $_GET;
                    
                    if (logTrafficData($data)) {
                        // GoProxy expects HTTP 204 for successful traffic report
                        http_response_code(204);
                        exit;
                    } else {
                        http_response_code(500);
                        echo json_encode(['error' => 'Failed to log traffic data']);
                    }
                }
                break;
                
            case 'POST':
                // Handle POST traffic data
                $input = json_decode(file_get_contents('php://input'), true);
                $data = $input ?: $_POST;
                
                if (logTrafficData($data)) {
                    successResponse(null, 'Traffic data logged successfully');
                } else {
                    errorResponse('Failed to log traffic data', 500);
                }
                break;
                
            default:
                errorResponse('Method not allowed', 405);
        }
        
    } catch (Exception $e) {
        logError("Traffic API error: " . $e->getMessage());
        errorResponse('Internal server error', 500);
    }
}

/**
 * Health check for traffic API
 */
function handleHealthCheck() {
    $health = [
        'status' => 'healthy',
        'timestamp' => time(),
        'service' => 'traffic'
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
    
    // Check recent traffic logs
    try {
        $db = getDatabase();
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM traffic_logs WHERE session_start >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        $stmt->execute();
        $result = $stmt->fetch();
        $health['recent_traffic_logs'] = $result['count'];
    } catch (Exception $e) {
        $health['recent_traffic_logs'] = 'error';
    }
    
    $statusCode = ($health['status'] === 'healthy') ? 200 : 503;
    jsonResponse($health, $statusCode);
}

// Handle the request
$action = $_GET['action'] ?? 'report';

if ($action === 'health') {
    handleHealthCheck();
} else {
    handleTrafficRequest();
}
?>
