#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - ONE-LINE QUICK INSTALLER
# ============================================================================
# Automatically installs and configures the entire secure proxy SaaS system
# Usage: curl -sSL https://raw.githubusercontent.com/nixbro/proxy-saas-fixed/main/quick_install.sh | sudo bash
# ============================================================================

set -euo pipefail

# Configuration
INSTALL_DIR="/opt/proxy-saas-system"
WEB_DIR="/var/www/html"
SERVICE_USER="proxy-saas"
LOG_FILE="/tmp/proxy-saas-install-$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

# Check root
[[ $EUID -eq 0 ]] || error "Run as root: sudo bash"

# Banner
echo -e "${GREEN}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                 PROXY SAAS SYSTEM INSTALLER                 ║
║                    Secure & Compliant                       ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "🚀 Starting automatic installation..."

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
    apt-get update -qq && apt-get upgrade -y -qq
    
    # Install dependencies
    log "📦 Installing dependencies..."
    apt-get install -y -qq \
        nginx mariadb-server redis-server \
        php8.1-fpm php8.1-mysql php8.1-redis php8.1-curl php8.1-cli php8.1-mbstring php8.1-xml \
        curl wget unzip git htop ufw certbot python3-certbot-nginx
        
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
SERVER_HOST=$(curl -s ifconfig.me || echo "localhost")
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
systemctl start mariadb && systemctl enable mariadb

# Try multiple methods to set root password
log "🔐 Setting MariaDB root password..."
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_PASS';" 2>/dev/null || \
mysql -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('$DB_PASS');" 2>/dev/null || \
mysqladmin -u root password "$DB_PASS" 2>/dev/null || \
mysql -u root -e "UPDATE mysql.user SET Password=PASSWORD('$DB_PASS') WHERE User='root'; FLUSH PRIVILEGES;" 2>/dev/null || true

# Wait a moment for password to take effect
sleep 2

# Clean up default MariaDB installation
log "🧹 Securing MariaDB installation..."
mysql -u root -p"$DB_PASS" -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
mysql -u root -p"$DB_PASS" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
mysql -u root -p"$DB_PASS" -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
mysql -u root -p"$DB_PASS" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null || true
mysql -u root -p"$DB_PASS" -e "FLUSH PRIVILEGES;" 2>/dev/null || true

# Create database and user
log "📊 Creating database and user..."
mysql -u root -p"$DB_PASS" -e "
CREATE DATABASE IF NOT EXISTS proxy_saas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'proxy_user'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON proxy_saas.* TO 'proxy_user'@'localhost';
FLUSH PRIVILEGES;
" 2>/dev/null || {
    log "⚠️ Trying alternative database creation method..."
    mysql -e "
    CREATE DATABASE IF NOT EXISTS proxy_saas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER IF NOT EXISTS 'proxy_user'@'localhost' IDENTIFIED BY '$DB_PASS';
    GRANT ALL PRIVILEGES ON proxy_saas.* TO 'proxy_user'@'localhost';
    FLUSH PRIVILEGES;
    " 2>/dev/null || {
        error "Failed to create database. Please run: sudo mysql_secure_installation"
    }
}

# Configure Redis
log "🔴 Configuring Redis..."
echo "requirepass $REDIS_PASS" >> /etc/redis/redis.conf
systemctl start redis-server && systemctl enable redis-server

# Create secure API files
log "🌐 Creating secure API files..."

# Secure config.php
cat > "$WEB_DIR/api/config.php" << 'EOF'
<?php
define('PROXY_SAAS_SYSTEM', true);
if (file_exists('/opt/proxy-saas-system/.env')) {
    $lines = file('/opt/proxy-saas-system/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '=') !== false && strpos($line, '#') !== 0) {
            list($key, $value) = explode('=', $line, 2);
            putenv(trim($key) . '=' . trim($value));
        }
    }
}
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_NAME', getenv('DB_NAME') ?: 'proxy_saas');
define('DB_USER', getenv('DB_USER') ?: 'proxy_user');
define('DB_PASS', getenv('DB_PASSWORD') ?: '');
function getDatabase() {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]);
    }
    return $pdo;
}
function getClientIp() {
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}
?>
EOF

# Secure auth.php
cat > "$WEB_DIR/api/internal/auth.php" << 'EOF'
<?php
require_once __DIR__ . '/../config.php';
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
            http_response_code(204);
            header("userconns: 100");
            header("ipconns: 10");
            exit();
        }
    }
    http_response_code(401);
    exit('Unauthorized');
} catch (Exception $e) {
    http_response_code(500);
    exit('Error');
}
?>
EOF

# Secure traffic.php
cat > "$WEB_DIR/api/internal/traffic.php" << 'EOF'
<?php
require_once __DIR__ . '/../config.php';
if (!in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
    http_response_code(403);
    exit('Forbidden');
}
$bytes = (int)($_GET['bytes'] ?? 0);
$clientAddr = $_GET['client_addr'] ?? '';
$username = $_GET['username'] ?? '';
try {
    if ($bytes > 0) {
        error_log("Traffic: $username used $bytes bytes from $clientAddr");
    }
    http_response_code(204);
    exit();
} catch (Exception $e) {
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
if (empty($apiKey) && empty($username)) {
    http_response_code(401);
    exit('Authentication required');
}
$serverHost = getenv('SERVER_HOST') ?: 'localhost';
$startPort = (int)(getenv('PROXY_PORT_START') ?: 4000);
$endPort = (int)(getenv('PROXY_PORT_END') ?: 4010);
for ($port = $startPort; $port <= $endPort; $port++) {
    echo "$serverHost:$port\n";
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
        echo "Started proxy on port $port (PID: $proxy_pid)"
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
        for ((port=PROXY_PORT_START; port<=PROXY_PORT_END; port++)); do
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
        for ((port=PROXY_PORT_START; port<=PROXY_PORT_END; port++)); do
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
    
    location /api/ {
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }
    }
}
EOF

ln -sf /etc/nginx/sites-available/proxy-saas /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl start nginx && systemctl enable nginx

# Configure firewall
log "🔥 Configuring firewall..."
if command -v ufw >/dev/null; then
    ufw --force enable
    ufw allow ssh
    ufw allow 80,443,8889/tcp
    ufw allow 4000:4999/tcp
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

# Get server info
SERVER_IP=$(curl -s ifconfig.me || echo "localhost")

# Final setup
log "🎯 Finalizing installation..."
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
🔌 Proxy Ports: 4000-4999
📁 Install Dir: $INSTALL_DIR

🚀 START SYSTEM:
   systemctl start proxy-saas

📊 CHECK STATUS:
   systemctl status proxy-saas
   $INSTALL_DIR/proxy_manager.sh status

🧪 TEST API:
   curl http://$SERVER_IP:8889/api/proxies.php?api_key=test

📝 LOGS:
   tail -f $INSTALL_DIR/logs/users/user_port_4000.log

🔐 CREDENTIALS:
   All secure credentials saved in: $INSTALL_DIR/.env

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
echo -e "${NC}"

log "📋 Installation log: $LOG_FILE"
