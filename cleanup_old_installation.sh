#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - COMPLETE CLEANUP SCRIPT
# ============================================================================
# 
# This script completely removes old installations and files
# Run this before installing the fixed version
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
OLD_INSTALL_DIR="/opt/$PROJECT_NAME"
OLD_WEB_DIR="/var/www/html"
SERVICE_USER="proxy-saas"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[CLEANUP]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Stop all related services
stop_services() {
    log_step "Stopping all related services..."
    
    local services=("$PROJECT_NAME" "nginx" "php8.1-fpm" "mariadb" "redis-server")
    
    for service in "${services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log_info "Stopping $service..."
            systemctl stop "$service" || true
        fi
    done
    
    log_success "Services stopped"
}

# Kill all proxy processes
kill_proxy_processes() {
    log_step "Killing all proxy processes..."
    
    # Kill all GoProxy processes
    pkill -f "proxy http" 2>/dev/null || true
    pkill -f "goproxy" 2>/dev/null || true
    
    # Kill processes on proxy ports
    for port in {4000..4999}; do
        local pid=$(lsof -ti:$port 2>/dev/null || echo "")
        if [[ -n "$pid" ]]; then
            log_info "Killing process on port $port (PID: $pid)"
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    
    log_success "Proxy processes killed"
}

# Remove systemd service
remove_systemd_service() {
    log_step "Removing systemd service..."
    
    if [[ -f "/etc/systemd/system/$PROJECT_NAME.service" ]]; then
        systemctl disable "$PROJECT_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/$PROJECT_NAME.service"
        systemctl daemon-reload
        log_success "Systemd service removed"
    else
        log_info "No systemd service found"
    fi
}

# Remove installation directories
remove_installation_dirs() {
    log_step "Removing installation directories..."
    
    # Remove main installation directory
    if [[ -d "$OLD_INSTALL_DIR" ]]; then
        log_info "Removing $OLD_INSTALL_DIR..."
        rm -rf "$OLD_INSTALL_DIR"
        log_success "Installation directory removed"
    else
        log_info "Installation directory not found"
    fi
    
    # Remove web API files
    if [[ -d "$OLD_WEB_DIR/api" ]]; then
        log_info "Removing $OLD_WEB_DIR/api..."
        rm -rf "$OLD_WEB_DIR/api"
        log_success "Web API directory removed"
    else
        log_info "Web API directory not found"
    fi
    
    # Remove log directories
    local log_dirs=("/var/log/$PROJECT_NAME" "/var/log/proxy-saas" "/var/log/goproxy")
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            log_info "Removing $log_dir..."
            rm -rf "$log_dir"
        fi
    done
    
    log_success "Directories cleaned"
}

# Remove nginx configuration
remove_nginx_config() {
    log_step "Removing nginx configuration..."
    
    local nginx_configs=(
        "/etc/nginx/sites-available/$PROJECT_NAME"
        "/etc/nginx/sites-enabled/$PROJECT_NAME"
        "/etc/nginx/sites-available/proxy-saas"
        "/etc/nginx/sites-enabled/proxy-saas"
        "/etc/nginx/sites-available/proxy-saas-system"
        "/etc/nginx/sites-enabled/proxy-saas-system"
    )
    
    for config in "${nginx_configs[@]}"; do
        if [[ -f "$config" ]]; then
            log_info "Removing $config..."
            rm -f "$config"
        fi
    done
    
    # Test nginx configuration
    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
        log_success "Nginx configuration cleaned"
    else
        log_warning "Nginx configuration has issues, please check manually"
    fi
}

# Remove service user
remove_service_user() {
    log_step "Removing service user..."
    
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "Removing user $SERVICE_USER..."
        userdel -r "$SERVICE_USER" 2>/dev/null || true
        log_success "Service user removed"
    else
        log_info "Service user not found"
    fi
}

# Clean database (optional)
clean_database() {
    log_step "Cleaning database..."
    
    read -p "Do you want to remove the database 'proxy_saas'? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if systemctl is-active mariadb >/dev/null 2>&1; then
            log_info "Removing database..."
            mysql -u root -p -e "DROP DATABASE IF EXISTS proxy_saas;" 2>/dev/null || true
            mysql -u root -p -e "DROP USER IF EXISTS 'proxy_user'@'localhost';" 2>/dev/null || true
            mysql -u root -p -e "FLUSH PRIVILEGES;" 2>/dev/null || true
            log_success "Database removed"
        else
            log_warning "MariaDB not running, skipping database cleanup"
        fi
    else
        log_info "Database cleanup skipped"
    fi
}

# Clean Redis data (optional)
clean_redis() {
    log_step "Cleaning Redis data..."
    
    read -p "Do you want to flush Redis data? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if systemctl is-active redis-server >/dev/null 2>&1; then
            log_info "Flushing Redis data..."
            redis-cli FLUSHALL 2>/dev/null || true
            log_success "Redis data flushed"
        else
            log_warning "Redis not running, skipping Redis cleanup"
        fi
    else
        log_info "Redis cleanup skipped"
    fi
}

# Remove old project files
remove_old_project_files() {
    log_step "Removing old project files..."
    
    # Common locations where old files might be
    local old_locations=(
        "$HOME/proxy-saas-system"
        "$HOME/proxy-saas"
        "$HOME/goproxy"
        "/tmp/proxy-saas-system"
        "/tmp/goproxy"
        "/tmp/proxy_install*"
        "/tmp/goproxy_install*"
    )
    
    for location in "${old_locations[@]}"; do
        if [[ -d "$location" ]] || [[ -f "$location" ]]; then
            log_info "Removing $location..."
            rm -rf "$location" 2>/dev/null || true
        fi
    done
    
    # Remove any downloaded archives
    find /tmp -name "*proxy*" -type f -mtime +1 -delete 2>/dev/null || true
    find /tmp -name "*goproxy*" -type f -mtime +1 -delete 2>/dev/null || true
    
    log_success "Old project files removed"
}

# Clean package cache
clean_package_cache() {
    log_step "Cleaning package cache..."
    
    apt-get autoremove -y 2>/dev/null || true
    apt-get autoclean 2>/dev/null || true
    
    log_success "Package cache cleaned"
}

# Remove GoProxy binary (optional)
remove_goproxy_binary() {
    log_step "Checking GoProxy binary..."
    
    if command -v proxy >/dev/null 2>&1; then
        read -p "Do you want to remove the GoProxy binary? (y/N): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            local proxy_path=$(which proxy)
            log_info "Removing GoProxy binary at $proxy_path..."
            rm -f "$proxy_path"
            log_success "GoProxy binary removed"
        else
            log_info "GoProxy binary kept (will be reused)"
        fi
    else
        log_info "GoProxy binary not found"
    fi
}

# Verify cleanup
verify_cleanup() {
    log_step "Verifying cleanup..."
    
    local issues=0
    
    # Check if service is still running
    if systemctl is-active "$PROJECT_NAME" >/dev/null 2>&1; then
        log_warning "Service $PROJECT_NAME is still running"
        ((issues++))
    fi
    
    # Check if installation directory exists
    if [[ -d "$OLD_INSTALL_DIR" ]]; then
        log_warning "Installation directory still exists: $OLD_INSTALL_DIR"
        ((issues++))
    fi
    
    # Check if web API directory exists
    if [[ -d "$OLD_WEB_DIR/api" ]]; then
        log_warning "Web API directory still exists: $OLD_WEB_DIR/api"
        ((issues++))
    fi
    
    # Check if service user exists
    if id "$SERVICE_USER" &>/dev/null; then
        log_warning "Service user still exists: $SERVICE_USER"
        ((issues++))
    fi
    
    # Check for running proxy processes
    if pgrep -f "proxy http" >/dev/null 2>&1; then
        log_warning "Proxy processes still running"
        ((issues++))
    fi
    
    if [[ $issues -eq 0 ]]; then
        log_success "Cleanup verification passed - system is clean"
    else
        log_warning "Cleanup verification found $issues issues"
        log_info "You may need to manually address the remaining issues"
    fi
}

# Main cleanup function
main() {
    echo "============================================================================"
    echo "PROXY-SAAS-SYSTEM - COMPLETE CLEANUP"
    echo "============================================================================"
    echo ""
    echo "This script will completely remove the old proxy-saas-system installation."
    echo "This includes:"
    echo "  - Stopping all services"
    echo "  - Removing installation files"
    echo "  - Removing systemd service"
    echo "  - Removing nginx configuration"
    echo "  - Removing service user"
    echo "  - Optionally removing database and Redis data"
    echo ""
    
    read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi
    
    echo ""
    log_info "Starting complete cleanup..."
    
    check_root
    stop_services
    kill_proxy_processes
    remove_systemd_service
    remove_installation_dirs
    remove_nginx_config
    remove_service_user
    remove_old_project_files
    clean_package_cache
    remove_goproxy_binary
    clean_database
    clean_redis
    verify_cleanup
    
    echo ""
    echo "============================================================================"
    log_success "CLEANUP COMPLETED!"
    echo "============================================================================"
    echo ""
    echo "Your system has been cleaned of all old proxy-saas-system installations."
    echo ""
    echo "Next steps:"
    echo "  1. Navigate to the proxy-saas-fixed folder"
    echo "  2. Run: sudo ./setup_complete.sh"
    echo "  3. Test with: sudo ./scripts/test_system.sh"
    echo ""
    echo "The system is now ready for a fresh installation!"
    echo ""
}

# Run main function
main "$@"
