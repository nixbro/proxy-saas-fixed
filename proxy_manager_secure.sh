#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - SECURE GOPROXY v15.x COMPLIANT MANAGER
# ============================================================================
# SECURITY FIXES APPLIED:
# ✅ Always includes AUTH_URL and TRAFFIC_URL (no conditional logic)
# ✅ User-specific logging with --log-file parameter
# ✅ Localhost-only API URLs (127.0.0.1)
# ✅ Removed --sniff-domain parameter per user preference
# ✅ Comprehensive error handling and validation
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/pids"
LOG_DIR="$SCRIPT_DIR/logs"
USER_LOG_DIR="$LOG_DIR/users"

# Load .env if exists
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    source "${SCRIPT_DIR}/.env"
fi

# Proxy configuration from .env with secure defaults
PROXY_START_PORT=${PROXY_PORT_START:-4000}
PROXY_END_PORT=${PROXY_PORT_END:-4010}

# GoProxy v15.x Compliant URLs - ALWAYS LOCALHOST for security
AUTH_URL=${AUTH_URL:-"http://127.0.0.1:8889/api/internal/auth.php"}
TRAFFIC_URL=${TRAFFIC_URL:-"http://127.0.0.1:8889/api/internal/traffic.php"}
CONTROL_URL=${CONTROL_URL:-"http://127.0.0.1:8889/api/internal/control.php"}

# Validate URLs are localhost-only for security
validate_localhost_urls() {
    local urls=("$AUTH_URL" "$TRAFFIC_URL" "$CONTROL_URL")
    for url in "${urls[@]}"; do
        if [[ ! "$url" =~ ^http://127\.0\.0\.1: ]]; then
            log_error "SECURITY ERROR: API URL must be localhost-only: $url"
            log_error "Expected format: http://127.0.0.1:PORT/path"
            return 1
        fi
    done
    return 0
}

# Constants
MAX_RETRY_ATTEMPTS=3
STARTUP_DELAY=2

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[INFO]${NC} $timestamp - $1"
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    echo "[$timestamp] [INFO] $1" >> "$LOG_DIR/manager.log" 2>/dev/null || true
}

log_success() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[SUCCESS]${NC} $timestamp - $1"
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    echo "[$timestamp] [SUCCESS] $1" >> "$LOG_DIR/manager.log" 2>/dev/null || true
}

log_warning() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[WARNING]${NC} $timestamp - $1"
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    echo "[$timestamp] [WARNING] $1" >> "$LOG_DIR/manager.log" 2>/dev/null || true
}

log_error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[ERROR]${NC} $timestamp - $1" >&2
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    echo "[$timestamp] [ERROR] $1" >> "$LOG_DIR/manager.log" 2>/dev/null || true
}

# Initialize directories
init_directories() {
    mkdir -p "$PID_DIR" "$LOG_DIR" "$USER_LOG_DIR"
    
    # Set proper permissions for log directories
    chmod 755 "$LOG_DIR" "$USER_LOG_DIR" 2>/dev/null || true
    
    log_info "Directories initialized: $PID_DIR, $LOG_DIR, $USER_LOG_DIR"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v proxy >/dev/null 2>&1; then
        log_error "GoProxy not found. Please install GoProxy first."
        log_error "Download from: https://github.com/snail007/goproxy/releases"
        return 1
    fi
    
    local version=$(proxy --version 2>&1 | head -1 || echo "unknown")
    log_success "GoProxy found: $version"
    
    # Validate localhost-only URLs
    if ! validate_localhost_urls; then
        return 1
    fi
    
    log_success "All dependencies and security checks passed"
    return 0
}

# Start a single proxy instance with user-specific logging
start_proxy_instance() {
    local port=$1
    local pid_file="$PID_DIR/proxy_${port}.pid"
    local user_log_file="$USER_LOG_DIR/user_port_${port}.log"
    
    # Check if already running
    if [[ -f "$pid_file" ]]; then
        local existing_pid=$(cat "$pid_file" 2>/dev/null || echo "")
        if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
            log_warning "Proxy already running on port $port (PID: $existing_pid)"
            return 0
        else
            rm -f "$pid_file"
        fi
    fi
    
    log_info "Starting GoProxy on port $port with user-specific logging"
    
    local attempt=1
    while [[ $attempt -le $MAX_RETRY_ATTEMPTS ]]; do
        log_info "Attempt $attempt/$MAX_RETRY_ATTEMPTS for port $port"
        
        # GoProxy v15.x Compliant Command - ALWAYS includes auth, traffic, and control
        # User preference: Always include authentication and traffic monitoring (not conditional)
        # User preference: --sniff-domain parameter removed
        # User requirement: --log-file parameter for user-specific logging
        local proxy_cmd="proxy http -p \":$port\" \
            --daemon \
            --auth-url \"$AUTH_URL\" \
            --auth-nouser \
            --auth-cache 300 \
            --traffic-url \"$TRAFFIC_URL\" \
            --traffic-mode fast \
            --traffic-interval 5 \
            --control-url \"$CONTROL_URL\" \
            --control-sleep 30 \
            --log-file \"$user_log_file\""

        log_info "Executing: $proxy_cmd"
        
        # Execute the command
        if eval "$proxy_cmd" >/dev/null 2>&1; then
            sleep $STARTUP_DELAY
            
            # Find the PID
            local proxy_pid=$(pgrep -f "proxy.*:$port" | head -1)
            
            if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
                echo "$proxy_pid" > "$pid_file"
                log_success "Proxy started on port $port (PID: $proxy_pid, Log: $user_log_file)"
                return 0
            else
                log_warning "Proxy process not found after start attempt"
            fi
        else
            log_warning "Proxy command failed on attempt $attempt"
        fi
        
        if [[ $attempt -lt $MAX_RETRY_ATTEMPTS ]]; then
            log_info "Retrying in 2 seconds..."
            sleep 2
        fi
        
        ((attempt++))
    done
    
    log_error "Failed to start proxy on port $port after $MAX_RETRY_ATTEMPTS attempts"
    return 1
}

# Stop a single proxy instance
stop_proxy_instance() {
    local port=$1
    local pid_file="$PID_DIR/proxy_${port}.pid"
    
    if [[ ! -f "$pid_file" ]]; then
        log_warning "No PID file found for port $port"
        return 0
    fi
    
    local pid=$(cat "$pid_file" 2>/dev/null || echo "")
    if [[ -z "$pid" ]]; then
        log_warning "Empty PID file for port $port"
        rm -f "$pid_file"
        return 0
    fi
    
    if kill -0 "$pid" 2>/dev/null; then
        log_info "Stopping proxy on port $port (PID: $pid)"
        if kill -TERM "$pid" 2>/dev/null; then
            # Wait for graceful shutdown
            local count=0
            while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
                sleep 1
                ((count++))
            done
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                log_warning "Force killing proxy on port $port"
                kill -KILL "$pid" 2>/dev/null || true
            fi
            
            log_success "Proxy stopped on port $port"
        else
            log_error "Failed to send TERM signal to PID $pid"
        fi
    else
        log_info "Proxy process not running for port $port"
    fi
    
    rm -f "$pid_file"
    return 0
}

# Start all proxy instances
start_all_proxies() {
    log_info "Starting all proxy instances (ports $PROXY_START_PORT-$PROXY_END_PORT)"
    
    local started_count=0
    local failed_count=0
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        if start_proxy_instance "$port"; then
            ((started_count++))
        else
            ((failed_count++))
        fi
        
        # Small delay between starts to avoid overwhelming the system
        sleep 0.1
    done
    
    log_success "Proxy startup completed: $started_count started, $failed_count failed"
    
    if [[ $failed_count -gt 0 ]]; then
        log_warning "Some proxies failed to start. Check logs for details."
        return 1
    fi
    
    return 0
}

# Stop all proxy instances
stop_all_proxies() {
    log_info "Stopping all proxy instances"
    
    local stopped_count=0
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        if stop_proxy_instance "$port"; then
            ((stopped_count++))
        fi
    done
    
    log_success "Stopped $stopped_count proxy instances"
    return 0
}

# Show status of all proxy instances
status_proxies() {
    log_info "Checking status of all proxy instances"
    
    local running_count=0
    local total_count=0
    
    echo ""
    printf "%-8s %-10s %-15s %-50s\n" "PORT" "STATUS" "PID" "LOG_FILE"
    printf "%-8s %-10s %-15s %-50s\n" "----" "------" "---" "--------"
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        local pid_file="$PID_DIR/proxy_${port}.pid"
        local user_log_file="$USER_LOG_DIR/user_port_${port}.log"
        local status="STOPPED"
        local pid=""
        
        ((total_count++))
        
        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file" 2>/dev/null || echo "")
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                status="RUNNING"
                ((running_count++))
            else
                status="DEAD"
                rm -f "$pid_file"
            fi
        fi
        
        printf "%-8s %-10s %-15s %-50s\n" "$port" "$status" "$pid" "$user_log_file"
    done
    
    echo ""
    log_info "Status: $running_count/$total_count proxies running"
    return 0
}

# Health check
health_check() {
    log_info "Performing health check"
    
    local healthy_count=0
    local total_count=0
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        local pid_file="$PID_DIR/proxy_${port}.pid"
        ((total_count++))
        
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file" 2>/dev/null || echo "")
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                ((healthy_count++))
            else
                log_warning "Proxy on port $port is not healthy (PID: $pid)"
                # Attempt to restart
                log_info "Attempting to restart proxy on port $port"
                stop_proxy_instance "$port"
                start_proxy_instance "$port"
            fi
        else
            log_warning "Proxy on port $port is not running"
            # Attempt to start
            log_info "Attempting to start proxy on port $port"
            start_proxy_instance "$port"
        fi
    done
    
    log_info "Health check completed: $healthy_count/$total_count proxies healthy"
    return 0
}

# Main execution
main() {
    init_directories
    
    case "${1:-}" in
        start)
            log_info "Starting Secure Proxy SaaS System"
            check_dependencies || exit 1
            start_all_proxies
            ;;
        stop)
            log_info "Stopping Secure Proxy SaaS System"
            stop_all_proxies
            ;;
        restart)
            log_info "Restarting Secure Proxy SaaS System"
            stop_all_proxies
            sleep 2
            check_dependencies || exit 1
            start_all_proxies
            ;;
        status)
            status_proxies
            ;;
        health)
            health_check
            ;;
        *)
            echo "Secure Proxy Manager (GoProxy v15.x Compliant)"
            echo "Usage: $0 {start|stop|restart|status|health}"
            echo ""
            echo "Security Features:"
            echo "  ✅ Always includes AUTH_URL and TRAFFIC_URL"
            echo "  ✅ User-specific logging with --log-file"
            echo "  ✅ Localhost-only API URLs (127.0.0.1)"
            echo "  ✅ Removed --sniff-domain parameter"
            echo "  ✅ Comprehensive error handling"
            echo ""
            echo "Configuration:"
            echo "  - Port range: $PROXY_START_PORT-$PROXY_END_PORT"
            echo "  - Auth URL: $AUTH_URL"
            echo "  - Traffic URL: $TRAFFIC_URL"
            echo "  - Control URL: $CONTROL_URL"
            echo "  - User logs: $USER_LOG_DIR/"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
