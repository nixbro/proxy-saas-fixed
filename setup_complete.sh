#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - COMPLETE INSTALLATION SCRIPT (FIXED VERSION)
# ============================================================================
# 
# This script installs the complete proxy SaaS system with all fixes applied
# Tested and verified to work on Ubuntu 22.04 LTS
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
PROJECT_NAME="proxy-saas-system"
INSTALL_DIR="/opt/$PROJECT_NAME"
WEB_DIR="/var/www/html"
SERVICE_USER="proxy-saas"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Database configuration
DB_NAME="proxy_saas"
DB_USER="proxy_user"
DB_PASSWORD="ProxySecure2024!"
DB_ROOT_PASSWORD="RootSecure2024!"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') - $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $(date '+%H:%M:%S') - $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Get server IP
get_server_ip() {
    local server_ip=""
    server_ip=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}' || echo "127.0.0.1")
    echo "$server_ip"
}

# Install dependencies
install_dependencies() {
    log_step "Installing system dependencies..."
    
    apt-get update -y
    apt-get install -y \
        curl wget unzip software-properties-common \
        nginx php8.1 php8.1-fpm php8.1-mysql php8.1-redis php8.1-curl php8.1-mbstring php8.1-xml \
        mariadb-server mariadb-client redis-server \
        net-tools bc jq htop nano vim \
        certbot python3-certbot-nginx
    
    log_success "Dependencies installed"
}

# Install GoProxy
install_goproxy() {
    log_step "Installing GoProxy..."
    
    if command -v proxy >/dev/null 2>&1; then
        log_success "GoProxy already installed"
        return 0
    fi
    
    local temp_dir="/tmp/goproxy_install"
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    if wget -q "https://github.com/snail007/goproxy/releases/download/v15.1/proxy-linux-amd64.tar.gz" -O proxy.tar.gz; then
        tar -xzf proxy.tar.gz
        chmod +x proxy
        mv proxy /usr/local/bin/
        log_success "GoProxy installed"
    else
        log_error "Failed to install GoProxy"
        exit 1
    fi
    
    rm -rf "$temp_dir"
}

# Setup database
setup_database() {
    log_step "Setting up MariaDB database..."
    
    systemctl start mariadb
    systemctl enable mariadb
    sleep 3
    
    # Set root password
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_ROOT_PASSWORD';" 2>/dev/null || \
    mysql -e "UPDATE mysql.user SET Password=PASSWORD('$DB_ROOT_PASSWORD') WHERE User='root';" 2>/dev/null || true
    
    mysql -u root -p"$DB_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    
    # Create database and user
    mysql -u root -p"$DB_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;" 2>/dev/null || true
    mysql -u root -p"$DB_ROOT_PASSWORD" -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';" 2>/dev/null || true
    mysql -u root -p"$DB_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';" 2>/dev/null || true
    mysql -u root -p"$DB_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    
    log_success "Database setup completed"
}

# Setup Redis
setup_redis() {
    log_step "Setting up Redis..."
    
    sed -i 's/^# requirepass.*/requirepass RedisSecure2024!/' /etc/redis/redis.conf
    sed -i 's/^bind 127.0.0.1.*/bind 127.0.0.1/' /etc/redis/redis.conf
    
    systemctl start redis-server
    systemctl enable redis-server
    
    log_success "Redis setup completed"
}

# Create service user and directories
setup_user_and_directories() {
    log_step "Creating service user and directories..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/bash -d "$INSTALL_DIR" "$SERVICE_USER"
    fi
    
    mkdir -p "$INSTALL_DIR"/{config,logs,pids,database}
    mkdir -p "$WEB_DIR/api/internal"
    mkdir -p "/var/log/$PROJECT_NAME"
    
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R www-data:www-data "$WEB_DIR"
    
    log_success "User and directories created"
}

# Copy and setup files
setup_files() {
    log_step "Setting up project files..."
    
    # Copy main files
    cp "$SCRIPT_DIR/proxy_manager.sh" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/config/system.conf" "$INSTALL_DIR/config/" 2>/dev/null || true
    
    # Copy API files
    cp "$SCRIPT_DIR/api/config.php" "$WEB_DIR/api/"
    cp "$SCRIPT_DIR/api/proxies.php" "$WEB_DIR/api/"
    cp "$SCRIPT_DIR/api/internal/auth.php" "$WEB_DIR/api/internal/"
    cp "$SCRIPT_DIR/api/internal/traffic.php" "$WEB_DIR/api/internal/" 2>/dev/null || true
    cp "$SCRIPT_DIR/api/internal/control.php" "$WEB_DIR/api/internal/" 2>/dev/null || true
    
    # Copy database files
    cp "$SCRIPT_DIR/database/schema.sql" "$INSTALL_DIR/database/"
    cp "$SCRIPT_DIR/database/sample_data.sql" "$INSTALL_DIR/database/" 2>/dev/null || true
    
    # Set permissions
    chmod +x "$INSTALL_DIR/proxy_manager.sh"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R www-data:www-data "$WEB_DIR"
    
    log_success "Files setup completed"
}

# Import database schema
import_database() {
    log_step "Importing database schema..."
    
    if [[ -f "$INSTALL_DIR/database/schema.sql" ]]; then
        mysql -u root -p"$DB_ROOT_PASSWORD" < "$INSTALL_DIR/database/schema.sql"
        log_success "Database schema imported"
    else
        log_error "Database schema file not found"
        exit 1
    fi
}

# Configure Nginx
configure_nginx() {
    log_step "Configuring Nginx..."
    
    local server_ip=$(get_server_ip)
    
    # Copy nginx configuration if exists, otherwise create basic one
    if [[ -f "$SCRIPT_DIR/nginx/proxy-saas.conf" ]]; then
        cp "$SCRIPT_DIR/nginx/proxy-saas.conf" "/etc/nginx/sites-available/$PROJECT_NAME"
        sed -i "s/SERVER_IP_PLACEHOLDER/$server_ip/g" "/etc/nginx/sites-available/$PROJECT_NAME"
    else
        cat > "/etc/nginx/sites-available/$PROJECT_NAME" << EOF
server {
    listen 8889;
    server_name $server_ip;
    root $WEB_DIR;
    index index.php index.html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # API endpoints
    location /api/ {
        try_files \$uri \$uri/ /api/proxies.php?\$query_string;
        
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ \.sql$ {
        deny all;
    }
}
EOF
    fi
    
    ln -sf "/etc/nginx/sites-available/$PROJECT_NAME" "/etc/nginx/sites-enabled/"
    nginx -t && systemctl reload nginx
    
    log_success "Nginx configured"
}

# Create systemd service
create_systemd_service() {
    log_step "Creating systemd service..."
    
    # Copy systemd service if exists, otherwise create basic one
    if [[ -f "$SCRIPT_DIR/systemd/proxy-saas-system.service" ]]; then
        cp "$SCRIPT_DIR/systemd/proxy-saas-system.service" "/etc/systemd/system/$PROJECT_NAME.service"
    else
        cat > "/etc/systemd/system/$PROJECT_NAME.service" << EOF
[Unit]
Description=Proxy SaaS System - Fixed Proxy Manager
After=network.target mariadb.service redis-server.service
Wants=mariadb.service redis-server.service

[Service]
Type=forking
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/proxy_manager.sh start
ExecStop=$INSTALL_DIR/proxy_manager.sh stop
ExecReload=$INSTALL_DIR/proxy_manager.sh restart
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    systemctl enable "$PROJECT_NAME"
    
    log_success "Systemd service created"
}

# Start services
start_services() {
    log_step "Starting all services..."
    
    systemctl start mariadb redis-server nginx php8.1-fpm
    systemctl start "$PROJECT_NAME"
    
    sleep 5
    
    log_success "All services started"
}

# Test installation
test_installation() {
    log_step "Testing installation..."
    
    local server_ip=$(get_server_ip)
    local errors=0
    
    # Test database
    if mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT 1;" >/dev/null 2>&1; then
        log_success "Database connection: OK"
    else
        log_error "Database connection: FAILED"
        ((errors++))
    fi
    
    # Test Redis
    if redis-cli -a "RedisSecure2024!" ping >/dev/null 2>&1; then
        log_success "Redis connection: OK"
    else
        log_error "Redis connection: FAILED"
        ((errors++))
    fi
    
    # Test API
    if curl -s "http://$server_ip:8889/api/proxies.php" >/dev/null 2>&1; then
        log_success "API endpoint: OK"
    else
        log_error "API endpoint: FAILED"
        ((errors++))
    fi
    
    # Test proxy service
    if systemctl is-active "$PROJECT_NAME" >/dev/null 2>&1; then
        log_success "Proxy service: RUNNING"
    else
        log_error "Proxy service: NOT RUNNING"
        ((errors++))
    fi
    
    return $errors
}

# Main installation function
main() {
    echo "============================================================================"
    echo "PROXY-SAAS-SYSTEM - COMPLETE FIXED INSTALLATION"
    echo "============================================================================"
    echo ""
    
    check_root
    
    log_info "Starting complete installation..."
    
    install_dependencies
    install_goproxy
    setup_database
    setup_redis
    setup_user_and_directories
    setup_files
    import_database
    configure_nginx
    create_systemd_service
    start_services
    
    echo ""
    log_info "Running installation tests..."
    
    if test_installation; then
        echo ""
        echo "============================================================================"
        log_success "INSTALLATION COMPLETED SUCCESSFULLY!"
        echo "============================================================================"
        echo ""
        local server_ip=$(get_server_ip)
        echo "System Information:"
        echo "  Server IP: $server_ip"
        echo "  API URL: http://$server_ip:8889/api/proxies.php"
        echo "  Proxy Ports: 4000-4010"
        echo "  Service Status: sudo systemctl status $PROJECT_NAME"
        echo "  Logs: sudo journalctl -u $PROJECT_NAME -f"
        echo ""
        echo "Test Commands:"
        echo "  curl http://$server_ip:8889/api/proxies.php"
        echo "  curl -x http://127.0.0.1:4000 http://httpbin.org/ip"
        echo ""
    else
        echo ""
        log_error "Installation completed with errors. Check the logs above."
        exit 1
    fi
}

# Run main function
main "$@"
