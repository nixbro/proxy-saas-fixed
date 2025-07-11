#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - LOCAL INSTALLATION SCRIPT
# ============================================================================
# Run this script directly on your server for immediate installation
# Usage: sudo bash install_local.sh
# ============================================================================

set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Banner
echo -e "${GREEN}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                 PROXY SAAS SYSTEM INSTALLER                 ║
║                    Local Installation                       ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "🚀 Starting local installation..."

# Configuration
INSTALL_DIR="/opt/proxy-saas-system"
WEB_DIR="/var/www/html"
SERVICE_USER="proxy-saas"

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
else
    error "Cannot detect OS"
fi

log "📋 Detected OS: $OS"

# Update system
log "📦 Updating system..."
if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq
    
    # Install dependencies
    log "📦 Installing dependencies..."
    apt-get install -y -qq \
        nginx mariadb-server redis-server \
        php8.1-fpm php8.1-mysql php8.1-redis php8.1-curl php8.1-cli php8.1-mbstring php8.1-xml \
        curl wget unzip git htop ufw
        
elif [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "fedora" ]]; then
    yum update -y -q
    yum install -y -q \
        nginx mariadb-server redis \
        php-fpm php-mysql php-redis php-curl php-cli php-mbstring php-xml \
        curl wget unzip git htop firewalld
fi

# Install GoProxy
log "📦 Installing GoProxy v15.x..."
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
wget -q "https://github.com/snail007/goproxy/releases/download/v15.1/proxy-linux-${ARCH}.tar.gz" -O /tmp/goproxy.tar.gz
tar -xzf /tmp/goproxy.tar.gz -C /tmp/
mv /tmp/proxy /usr/local/bin/
chmod +x /usr/local/bin/proxy
rm -f /tmp/goproxy.tar.gz

# Verify GoProxy installation
if ! proxy --version >/dev/null 2>&1; then
    error "GoProxy installation failed"
fi

success "GoProxy v15.x installed successfully"

# Create user and directories
log "👤 Setting up system user and directories..."
useradd -r -s /bin/bash -d "$INSTALL_DIR" "$SERVICE_USER" 2>/dev/null || true
mkdir -p "$INSTALL_DIR"/{api,database,logs,pids,scripts}
mkdir -p "$INSTALL_DIR/logs/users"
mkdir -p "$WEB_DIR/api/internal"

# Generate secure passwords
log "🔐 Generating secure credentials..."
DB_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
REDIS_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
API_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
JWT_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
ENCRYPT_KEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "localhost")

# Create secure .env file
log "⚙️ Creating secure configuration..."
cat > "$INSTALL_DIR/.env" << EOF
# PROXY-SAAS-SYSTEM - SECURE AUTO-GENERATED CONFIGURATION
DB_HOST=localhost
DB_PORT=3306
DB_NAME=proxy_saas
DB_USER=proxy_user
DB_PASSWORD=$DB_PASS
DB_CHARSET=utf8mb4
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=$REDIS_PASS
REDIS_DATABASE=0
PROXY_PORT_START=4000
PROXY_PORT_END=4999
AUTH_URL=http://127.0.0.1:8889/api/internal/auth.php
TRAFFIC_URL=http://127.0.0.1:8889/api/internal/traffic.php
CONTROL_URL=http://127.0.0.1:8889/api/internal/control.php
WEB_SERVER_HOST=127.0.0.1
WEB_SERVER_PORT=8889
SERVER_HOST=$SERVER_IP
API_SECRET_KEY=$API_SECRET
JWT_SECRET=$JWT_SECRET
ENCRYPTION_KEY=$ENCRYPT_KEY
ALLOWED_ORIGINS=https://localhost,https://127.0.0.1
DEFAULT_USER_QUOTA_GB=5
MAX_PROXY_POOL_SIZE=5000
APP_ENV=production
APP_DEBUG=false
TIMEZONE=UTC
EOF

# Configure MariaDB
log "🗄️ Configuring MariaDB..."
systemctl start mariadb
systemctl enable mariadb

# Secure MariaDB and create database
mysql -e "UPDATE mysql.user SET Password=PASSWORD('$DB_PASS') WHERE User='root';" 2>/dev/null || true
mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null || true
mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true

# Create database and user
mysql -u root -p"$DB_PASS" -e "
CREATE DATABASE IF NOT EXISTS proxy_saas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'proxy_user'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON proxy_saas.* TO 'proxy_user'@'localhost';
FLUSH PRIVILEGES;
" 2>/dev/null || mysql -e "
CREATE DATABASE IF NOT EXISTS proxy_saas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'proxy_user'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON proxy_saas.* TO 'proxy_user'@'localhost';
FLUSH PRIVILEGES;
"

# Create basic database schema
mysql -u proxy_user -p"$DB_PASS" proxy_saas << 'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) UNIQUE,
    status ENUM('active', 'suspended', 'banned') DEFAULT 'active',
    quota_bytes BIGINT DEFAULT 5368709120,
    bytes_used BIGINT DEFAULT 0,
    max_threads INT DEFAULT 100,
    expires_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_ip_whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    ip_range VARCHAR(50),
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS upstream_proxies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL,
    username VARCHAR(100),
    password VARCHAR(255),
    protocol ENUM('http', 'https', 'socks5') DEFAULT 'http',
    local_port INT UNIQUE,
    status ENUM('active', 'inactive', 'error') DEFAULT 'active',
    last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test user
INSERT IGNORE INTO users (username, password_hash, api_key, status) VALUES 
('testuser', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'test_api_key_12345', 'active');
EOF

success "Database configured successfully"

# Configure Redis
log "🔴 Configuring Redis..."
echo "requirepass $REDIS_PASS" >> /etc/redis/redis.conf
systemctl start redis-server
systemctl enable redis-server

# Create secure API files
log "🌐 Creating secure API files..."

# Secure config.php
cat > "$WEB_DIR/api/config.php" << 'EOF'
<?php
define('PROXY_SAAS_SYSTEM', true);

// Load environment variables
if (file_exists('/opt/proxy-saas-system/.env')) {
    $lines = file('/opt/proxy-saas-system/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '=') !== false && strpos($line, '#') !== 0) {
            list($key, $value) = explode('=', $line, 2);
            putenv(trim($key) . '=' . trim($value));
        }
    }
}

// Database configuration
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_NAME', getenv('DB_NAME') ?: 'proxy_saas');
define('DB_USER', getenv('DB_USER') ?: 'proxy_user');
define('DB_PASS', getenv('DB_PASSWORD') ?: '');

// Database connection function
function getDatabase() {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            exit('Database connection failed');
        }
    }
    return $pdo;
}

// Get client IP
function getClientIp() {
    $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    foreach ($ip_keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ips = explode(',', $_SERVER[$key]);
            $ip = trim($ips[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}
?>
EOF

# Secure auth.php
cat > "$WEB_DIR/api/internal/auth.php" << 'EOF'
<?php
require_once __DIR__ . '/../config.php';

// Security: Only allow localhost access
if (!in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
    http_response_code(403);
    exit('Forbidden');
}

$username = $_GET['user'] ?? '';
$password = $_GET['pass'] ?? '';
$clientIp = getClientIp();

try {
    $pdo = getDatabase();
    
    if (!empty($username)) {
        $stmt = $pdo->prepare("SELECT id, username, password_hash, status FROM users WHERE username = ? AND status = 'active'");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password_hash'])) {
            // GoProxy v15.x compliant response - HTTP 204
            http_response_code(204);
            header("userconns: 100");
            header("ipconns: 10");
            header("userrate: 1000");
            header("iprate: 100");
            exit();
        }
    }
    
    http_response_code(401);
    exit('Unauthorized');
    
} catch (Exception $e) {
    error_log("Auth error: " . $e->getMessage());
    http_response_code(500);
    exit('Error');
}
?>
EOF

# Secure traffic.php
cat > "$WEB_DIR/api/internal/traffic.php" << 'EOF'
<?php
require_once __DIR__ . '/../config.php';

// Security: Only allow localhost access
if (!in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
    http_response_code(403);
    exit('Forbidden');
}

$bytes = (int)($_GET['bytes'] ?? 0);
$clientAddr = $_GET['client_addr'] ?? '';
$username = $_GET['username'] ?? '';

try {
    if ($bytes > 0 && !empty($username)) {
        $pdo = getDatabase();
        $stmt = $pdo->prepare("UPDATE users SET bytes_used = bytes_used + ? WHERE username = ?");
        $stmt->execute([$bytes, $username]);
        
        error_log("Traffic: $username used $bytes bytes from $clientAddr");
    }
    
    // GoProxy v15.x compliant response - HTTP 204
    http_response_code(204);
    exit();
    
} catch (Exception $e) {
    error_log("Traffic error: " . $e->getMessage());
    http_response_code(500);
    exit('Error');
}
?>
EOF

# Secure proxies.php
cat > "$WEB_DIR/api/proxies.php" << 'EOF'
<?php
require_once __DIR__ . '/config.php';

header('Content-Type: text/plain');

$apiKey = $_GET['api_key'] ?? '';
$username = $_GET['username'] ?? '';
$password = $_GET['password'] ?? '';

if (empty($apiKey) && empty($username)) {
    http_response_code(401);
    exit('Authentication required');
}

try {
    $pdo = getDatabase();
    $user = null;
    
    if (!empty($apiKey)) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE api_key = ? AND status = 'active'");
        $stmt->execute([$apiKey]);
        $user = $stmt->fetch();
    } elseif (!empty($username) && !empty($password)) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND status = 'active'");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        if ($user && !password_verify($password, $user['password_hash'])) {
            $user = null;
        }
    }
    
    if (!$user) {
        http_response_code(401);
        exit('Invalid credentials');
    }
    
    // Check quota
    if ($user['bytes_used'] >= $user['quota_bytes']) {
        http_response_code(403);
        exit('Quota exceeded');
    }
    
    // Return proxy list
    $serverHost = getenv('SERVER_HOST') ?: 'localhost';
    $startPort = (int)(getenv('PROXY_PORT_START') ?: 4000);
    $endPort = min($startPort + 10, (int)(getenv('PROXY_PORT_END') ?: 4010)); // Limit to 10 proxies for demo
    
    for ($port = $startPort; $port <= $endPort; $port++) {
        echo "$serverHost:$port\n";
    }
    
} catch (Exception $e) {
    error_log("Proxies API error: " . $e->getMessage());
    http_response_code(500);
    exit('Internal server error');
}
?>
EOF

# Create proxy manager
log "🔧 Creating secure proxy manager..."
cat > "$INSTALL_DIR/proxy_manager.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

PID_DIR="$SCRIPT_DIR/pids"
LOG_DIR="$SCRIPT_DIR/logs/users"

mkdir -p "$PID_DIR" "$LOG_DIR"

start_proxy() {
    local port=$1
    local pid_file="$PID_DIR/proxy_${port}.pid"
    local log_file="$LOG_DIR/user_port_${port}.log"
    
    if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        echo "Proxy already running on port $port"
        return 0
    fi
    
    # GoProxy v15.x compliant command with user-specific logging
    proxy http -p ":$port" \
        --daemon \
        --auth-url "$AUTH_URL" \
        --auth-nouser \
        --auth-cache 300 \
        --traffic-url "$TRAFFIC_URL" \
        --traffic-mode fast \
        --traffic-interval 5 \
        --log-file "$log_file" >/dev/null 2>&1
    
    sleep 1
    local proxy_pid=$(pgrep -f "proxy.*:$port" | head -1)
    if [[ -n "$proxy_pid" ]]; then
        echo "$proxy_pid" > "$pid_file"
        echo "Started proxy on port $port (PID: $proxy_pid, Log: $log_file)"
    fi
}

stop_proxy() {
    local port=$1
    local pid_file="$PID_DIR/proxy_${port}.pid"
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "Stopped proxy on port $port"
        fi
        rm -f "$pid_file"
    fi
}

case "${1:-}" in
    start)
        echo "Starting proxy pool (ports $PROXY_PORT_START-$PROXY_PORT_END)..."
        # Start only first 10 proxies for demo
        end_port=$((PROXY_PORT_START + 9))
        for ((port=PROXY_PORT_START; port<=end_port; port++)); do
            start_proxy "$port"
        done
        ;;
    stop)
        echo "Stopping proxy pool..."
        for ((port=PROXY_PORT_START; port<=PROXY_PORT_END; port++)); do
            stop_proxy "$port"
        done
        ;;
    status)
        echo "Proxy Status:"
        end_port=$((PROXY_PORT_START + 9))
        for ((port=PROXY_PORT_START; port<=end_port; port++)); do
            local pid_file="$PID_DIR/proxy_${port}.pid"
            if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
                echo "Port $port: RUNNING (PID: $(cat "$pid_file"))"
            else
                echo "Port $port: STOPPED"
            fi
        done
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        ;;
esac
EOF

chmod +x "$INSTALL_DIR/proxy_manager.sh"

# Configure Nginx
log "🌐 Configuring Nginx..."
cat > /etc/nginx/sites-available/proxy-saas << 'EOF'
server {
    listen 8889;
    server_name localhost 127.0.0.1;
    root /var/www/html;
    index index.php index.html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Block external access to internal APIs
    location /api/internal/ {
        allow 127.0.0.1;
        deny all;
        
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }
    }
    
    # Public API access
    location /api/ {
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ \.env {
        deny all;
    }
}
EOF

ln -sf /etc/nginx/sites-available/proxy-saas /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl start nginx
systemctl enable nginx

# Configure firewall
log "🔥 Configuring firewall..."
if command -v ufw >/dev/null; then
    ufw --force enable
    ufw allow ssh
    ufw allow 80,443,8889/tcp
    ufw allow 4000:4010/tcp
fi

# Set permissions
log "🔐 Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chown -R www-data:www-data "$WEB_DIR"
chmod 600 "$INSTALL_DIR/.env"

# Create systemd service
log "⚙️ Creating systemd service..."
cat > /etc/systemd/system/proxy-saas.service << EOF
[Unit]
Description=Proxy SaaS System
After=network.target

[Service]
Type=forking
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/proxy_manager.sh start
ExecStop=$INSTALL_DIR/proxy_manager.sh stop
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-saas

# Start the system
log "🚀 Starting proxy system..."
systemctl start proxy-saas

# Final setup
success "✅ Installation completed successfully!"

echo -e "${GREEN}"
cat << EOF

╔══════════════════════════════════════════════════════════════╗
║                    INSTALLATION COMPLETE!                   ║
╚══════════════════════════════════════════════════════════════╝

🎉 PROXY SAAS SYSTEM READY!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📍 Server IP: $SERVER_IP
🚪 API Port: 8889
🔌 Proxy Ports: 4000-4009 (demo - 10 proxies)
📁 Install Dir: $INSTALL_DIR

🧪 TEST COMMANDS:
   # Test proxy list API
   curl http://$SERVER_IP:8889/api/proxies.php?api_key=test_api_key_12345
   
   # Test authentication (should return HTTP 204)
   curl -I http://127.0.0.1:8889/api/internal/auth.php?user=testuser&pass=password
   
   # Check proxy status
   $INSTALL_DIR/proxy_manager.sh status

📊 SYSTEM MANAGEMENT:
   systemctl status proxy-saas
   systemctl restart proxy-saas
   tail -f $INSTALL_DIR/logs/users/user_port_4000.log

🔐 CREDENTIALS:
   Database: proxy_saas
   Username: proxy_user
   Password: $DB_PASS
   
   Test User: testuser
   API Key: test_api_key_12345

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
echo -e "${NC}"

log "🎯 System is ready for production use!"
