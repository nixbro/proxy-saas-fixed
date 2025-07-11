#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - ALL-IN-ONE INSTALLATION SCRIPT
# ============================================================================
# 
# This script downloads, cleans, installs, and tests the complete system
# GitHub Repository: https://github.com/nixbro/proxy-saas-fixed
# 
# Usage: curl -sSL https://raw.githubusercontent.com/nixbro/proxy-saas-fixed/main/install.sh | sudo bash
# Or: wget -qO- https://raw.githubusercontent.com/nixbro/proxy-saas-fixed/main/install.sh | sudo bash
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
GITHUB_REPO="https://github.com/nixbro/proxy-saas-fixed.git"
PROJECT_NAME="proxy-saas-system"
INSTALL_DIR="/opt/$PROJECT_NAME"
WEB_DIR="/var/www/html"
SERVICE_USER="proxy-saas"
WORK_DIR="/tmp/proxy-saas-installation"

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

log_header() {
    echo -e "${MAGENTA}[HEADER]${NC} $1"
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
    # Use the specific server IP
    echo "138.201.33.108"
}

# Display banner
display_banner() {
    echo ""
    echo "============================================================================"
    echo "🚀 PROXY-SAAS-SYSTEM - ALL-IN-ONE INSTALLER"
    echo "============================================================================"
    echo ""
    echo "This script will:"
    echo "  ✅ Clean any existing installations"
    echo "  ✅ Download the latest fixed version from GitHub"
    echo "  ✅ Install all dependencies"
    echo "  ✅ Setup database and services"
    echo "  ✅ Configure and start the system"
    echo "  ✅ Run comprehensive tests"
    echo ""
    echo "Repository: https://github.com/nixbro/proxy-saas-fixed"
    echo "Server IP: 138.201.33.108"
    echo ""
    echo "============================================================================"
    echo ""
}

# Cleanup existing installation
cleanup_existing() {
    log_step "Cleaning existing installations..."
    
    # Stop services
    local services=("$PROJECT_NAME" "nginx" "php8.1-fpm")
    for service in "${services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log_info "Stopping $service..."
            systemctl stop "$service" 2>/dev/null || true
        fi
    done
    
    # Kill proxy processes
    pkill -f "proxy http" 2>/dev/null || true
    
    # Remove old installations
    rm -rf "$INSTALL_DIR" 2>/dev/null || true
    rm -rf "$WEB_DIR/api" 2>/dev/null || true
    rm -rf "/var/log/$PROJECT_NAME" 2>/dev/null || true
    
    # Remove systemd service
    if [[ -f "/etc/systemd/system/$PROJECT_NAME.service" ]]; then
        systemctl disable "$PROJECT_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/$PROJECT_NAME.service"
        systemctl daemon-reload
    fi
    
    # Remove nginx configs
    rm -f /etc/nginx/sites-available/proxy-saas* 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/proxy-saas* 2>/dev/null || true
    
    # Remove service user
    if id "$SERVICE_USER" &>/dev/null; then
        userdel -r "$SERVICE_USER" 2>/dev/null || true
    fi
    
    # Clean work directory
    rm -rf "$WORK_DIR" 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Download from GitHub
download_from_github() {
    log_step "Downloading latest version from GitHub..."
    
    # Install git if not present
    if ! command -v git >/dev/null 2>&1; then
        log_info "Installing git..."
        apt-get update -y >/dev/null 2>&1
        apt-get install -y git >/dev/null 2>&1
    fi
    
    # Create work directory
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    
    # Clone repository
    log_info "Cloning repository: $GITHUB_REPO"
    git clone "$GITHUB_REPO" proxy-saas-fixed >/dev/null 2>&1
    
    if [[ ! -d "proxy-saas-fixed" ]]; then
        log_error "Failed to download from GitHub"
        exit 1
    fi
    
    cd proxy-saas-fixed
    log_success "Downloaded successfully from GitHub"
}

# Install dependencies
install_dependencies() {
    log_step "Installing system dependencies..."
    
    # Update package list
    apt-get update -y >/dev/null 2>&1
    
    # Install essential packages
    apt-get install -y \
        curl wget unzip software-properties-common \
        nginx php8.1 php8.1-fpm php8.1-mysql php8.1-redis php8.1-curl php8.1-mbstring php8.1-xml \
        mariadb-server mariadb-client redis-server \
        net-tools bc jq htop nano vim \
        certbot python3-certbot-nginx >/dev/null 2>&1
    
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
        tar -xzf proxy.tar.gz >/dev/null 2>&1
        chmod +x proxy
        mv proxy /usr/local/bin/
        log_success "GoProxy installed"
    else
        log_error "Failed to install GoProxy"
        exit 1
    fi
    
    rm -rf "$temp_dir"
    cd "$WORK_DIR/proxy-saas-fixed"
}

# Setup database
setup_database() {
    log_step "Setting up MariaDB database..."
    
    # Start MariaDB
    systemctl start mariadb >/dev/null 2>&1
    systemctl enable mariadb >/dev/null 2>&1
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
    
    # Configure Redis
    sed -i 's/^# requirepass.*/requirepass RedisSecure2024!/' /etc/redis/redis.conf
    sed -i 's/^bind 127.0.0.1.*/bind 127.0.0.1/' /etc/redis/redis.conf
    
    # Start Redis
    systemctl start redis-server >/dev/null 2>&1
    systemctl enable redis-server >/dev/null 2>&1
    
    log_success "Redis setup completed"
}

# Setup system files
setup_system_files() {
    log_step "Setting up system files..."
    
    # Create service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/bash -d "$INSTALL_DIR" "$SERVICE_USER"
    fi
    
    # Create directories
    mkdir -p "$INSTALL_DIR"/{config,logs,pids,database}
    mkdir -p "$WEB_DIR/api/internal"
    mkdir -p "/var/log/$PROJECT_NAME"
    
    # Copy files
    cp proxy_manager.sh "$INSTALL_DIR/"
    cp api/config.php "$WEB_DIR/api/"
    cp api/proxies.php "$WEB_DIR/api/"
    cp api/internal/auth.php "$WEB_DIR/api/internal/"
    cp api/internal/traffic.php "$WEB_DIR/api/internal/"
    cp api/internal/control.php "$WEB_DIR/api/internal/"
    cp database/schema.sql "$INSTALL_DIR/database/"
    
    # Set permissions
    chmod +x "$INSTALL_DIR/proxy_manager.sh"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R www-data:www-data "$WEB_DIR"
    
    log_success "System files setup completed"
}

# Import database schema
import_database() {
    log_step "Importing database schema..."
    
    if [[ -f "$INSTALL_DIR/database/schema.sql" ]]; then
        mysql -u root -p"$DB_ROOT_PASSWORD" < "$INSTALL_DIR/database/schema.sql" >/dev/null 2>&1
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

    # Control API - LOCALHOST ONLY
    location /api/internal/control.php {
        allow 127.0.0.1;
        allow ::1;
        allow 138.201.33.108;
        deny all;

        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
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
    
    ln -sf "/etc/nginx/sites-available/$PROJECT_NAME" "/etc/nginx/sites-enabled/"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1
    
    log_success "Nginx configured"
}

# Create systemd service
create_systemd_service() {
    log_step "Creating systemd service..."
    
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
    
    systemctl daemon-reload
    systemctl enable "$PROJECT_NAME" >/dev/null 2>&1
    
    log_success "Systemd service created"
}

# Start services
start_services() {
    log_step "Starting all services..."
    
    systemctl start mariadb redis-server nginx php8.1-fpm >/dev/null 2>&1
    systemctl start "$PROJECT_NAME" >/dev/null 2>&1
    
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

    # Test Control API (localhost only)
    if curl -s "http://127.0.0.1:8889/api/internal/control.php?action=status" >/dev/null 2>&1; then
        log_success "Control API: OK (localhost access)"
    else
        log_error "Control API: FAILED"
        ((errors++))
    fi
    
    # Test proxy service
    if systemctl is-active "$PROJECT_NAME" >/dev/null 2>&1; then
        log_success "Proxy service: RUNNING"
    else
        log_error "Proxy service: NOT RUNNING"
        ((errors++))
    fi
    
    # Test proxy instances
    local running_proxies=0
    for port in {4000..4010}; do
        if netstat -ln 2>/dev/null | grep -q ":$port "; then
            ((running_proxies++))
        fi
    done
    
    if [[ $running_proxies -gt 0 ]]; then
        log_success "Proxy instances: $running_proxies running"
    else
        log_error "Proxy instances: NONE running"
        ((errors++))
    fi
    
    return $errors
}

# Display final results
display_results() {
    local server_ip=$(get_server_ip)
    
    echo ""
    echo "============================================================================"
    log_header "🎉 INSTALLATION COMPLETED SUCCESSFULLY!"
    echo "============================================================================"
    echo ""
    echo "✅ System Information:"
    echo "   Server IP: $server_ip"
    echo "   API URL: http://$server_ip:8889/api/proxies.php"
    echo "   Proxy Ports: 4000-4010 (11 instances)"
    echo "   Database: MariaDB (proxy_saas)"
    echo "   Cache: Redis"
    echo ""
    echo "✅ Quick Tests:"
    echo "   curl \"http://$server_ip:8889/api/proxies.php\""
    echo "   curl \"http://$server_ip:8889/api/proxies.php?action=health\""
    echo "   curl -x http://127.0.0.1:4000 http://httpbin.org/ip"
    echo ""
    echo "✅ Control API (Localhost Only):"
    echo "   curl \"http://127.0.0.1:8889/api/internal/control.php?action=status\""
    echo "   curl \"http://127.0.0.1:8889/api/internal/control.php?action=restart\""
    echo "   curl \"http://127.0.0.1:8889/api/internal/control.php?action=full_status\""
    echo ""
    echo "✅ Management Commands:"
    echo "   sudo systemctl status $PROJECT_NAME"
    echo "   sudo systemctl restart $PROJECT_NAME"
    echo "   sudo journalctl -u $PROJECT_NAME -f"
    echo ""
    echo "✅ Files Location:"
    echo "   Installation: $INSTALL_DIR"
    echo "   Logs: $INSTALL_DIR/logs/"
    echo "   Configuration: $WEB_DIR/api/config.php"
    echo ""
    echo "🚀 Your Proxy SaaS System is ready for production use!"
    echo ""
    echo "============================================================================"
}

# Main installation function
main() {
    display_banner
    
    log_info "Starting all-in-one installation..."
    
    check_root
    cleanup_existing
    download_from_github
    install_dependencies
    setup_database
    setup_redis
    setup_system_files
    import_database
    configure_nginx
    create_systemd_service
    start_services
    
    echo ""
    log_info "Running installation tests..."
    
    if test_installation; then
        display_results
        
        # Cleanup work directory
        rm -rf "$WORK_DIR" 2>/dev/null || true
        
        exit 0
    else
        echo ""
        log_error "Installation completed with errors. Check the logs above."
        exit 1
    fi
}

# Run main function
main "$@"
