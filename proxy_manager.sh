#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - UNIVERSAL PROXY MANAGER (FIXED VERSION)
# ============================================================================
# 
# Universal proxy manager that works with ANY GoProxy version
# Fixes all known issues and provides robust proxy management
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/pids"
LOG_DIR="$SCRIPT_DIR/logs"
LOCK_FILE="$SCRIPT_DIR/proxy_manager.lock"

# Proxy configuration
PROXY_START_PORT=4000
PROXY_END_PORT=4010
MAX_RETRY_ATTEMPTS=3
RESTART_DELAY=2

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
    echo -e "${RED}[ERROR]${NC} $timestamp - $1"
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    echo "[$timestamp] [ERROR] $1" >> "$LOG_DIR/manager.log" 2>/dev/null || true
}

# Lock management
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            log_error "Another instance is already running (PID: $lock_pid)"
            exit 1
        else
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE" 2>/dev/null || true
}

# Cleanup on exit
cleanup() {
    release_lock
}

trap cleanup EXIT

# Initialize directories
init_directories() {
    mkdir -p "$PID_DIR" "$LOG_DIR" 2>/dev/null || true
    log_info "Directories initialized"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v proxy >/dev/null 2>&1; then
        log_error "GoProxy not found. Please install GoProxy first."
        return 1
    fi
    
    local version=$(proxy --version 2>&1 | head -1 || echo "unknown")
    log_success "GoProxy found: $version"
    
    # Detect GoProxy capabilities
    if proxy http --help 2>&1 | grep -q "log-file"; then
        log_info "Commercial GoProxy features detected"
        echo "commercial" > "$SCRIPT_DIR/.goproxy_version"
    else
        log_info "Free GoProxy version detected"
        echo "free" > "$SCRIPT_DIR/.goproxy_version"
    fi
    
    return 0
}

# Start a single proxy instance
start_proxy_instance() {
    local port=$1
    local pid_file="$PID_DIR/proxy_${port}.pid"
    
    log_info "Starting proxy on port $port"
    
    # Remove stale PID file
    if [[ -f "$pid_file" ]]; then
        local old_pid=$(cat "$pid_file" 2>/dev/null || echo "")
        if [[ -n "$old_pid" ]] && ! kill -0 "$old_pid" 2>/dev/null; then
            rm -f "$pid_file"
        fi
    fi
    
    local attempt=1
    while [[ $attempt -le $MAX_RETRY_ATTEMPTS ]]; do
        log_info "Attempt $attempt/$MAX_RETRY_ATTEMPTS for port $port"
        
        # Build proxy command (works with both free and commercial)
        local proxy_cmd="proxy http -p \":$port\" --daemon"
        
        # Execute the command
        if eval "$proxy_cmd" >/dev/null 2>&1; then
            sleep 2
            
            # Find the PID
            local proxy_pid=$(pgrep -f "proxy.*:$port" | head -1)
            
            if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
                echo "$proxy_pid" > "$pid_file"
                log_success "Proxy started on port $port (PID: $proxy_pid)"
                return 0
            fi
        fi
        
        log_warning "Failed to start proxy on port $port (attempt $attempt)"
        
        if [[ $attempt -lt $MAX_RETRY_ATTEMPTS ]]; then
            sleep $RESTART_DELAY
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
    
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            
            # Wait for graceful shutdown
            local count=0
            while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
                sleep 1
                ((count++))
            done
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
                log_warning "Force killed proxy on port $port"
            else
                log_info "Gracefully stopped proxy on port $port"
            fi
        fi
        rm -f "$pid_file"
    fi
    
    # Kill any remaining processes on this port
    pkill -f "proxy.*:$port" 2>/dev/null || true
}

# Start all proxy instances
start_all_proxies() {
    log_info "Starting proxy pool (ports $PROXY_START_PORT-$PROXY_END_PORT)"
    
    local started_count=0
    local failed_count=0
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        if start_proxy_instance "$port"; then
            ((started_count++))
        else
            ((failed_count++))
        fi
    done
    
    log_info "Proxy pool startup: $started_count started, $failed_count failed"
    
    if [[ $started_count -eq 0 ]]; then
        log_error "No proxy instances started successfully"
        return 1
    fi
    
    return 0
}

# Stop all proxy instances
stop_all_proxies() {
    log_info "Stopping all proxy instances..."
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        stop_proxy_instance "$port"
    done
    
    # Kill any remaining proxy processes
    pkill -f "proxy http" 2>/dev/null || true
    
    # Clean up PID files
    rm -f "$PID_DIR"/proxy_*.pid 2>/dev/null || true
    
    log_success "All proxy instances stopped"
}

# Check status of proxy instances
status_proxies() {
    log_info "Checking proxy status..."
    
    local running_count=0
    local total_count=$((PROXY_END_PORT - PROXY_START_PORT + 1))
    
    echo "Proxy Status Report:"
    echo "==================="
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        local pid_file="$PID_DIR/proxy_${port}.pid"
        local status="STOPPED"
        local pid=""
        
        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file" 2>/dev/null || echo "")
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                status="RUNNING"
                ((running_count++))
                
                # Check if port is listening
                if netstat -ln 2>/dev/null | grep -q ":$port "; then
                    status="RUNNING (LISTENING)"
                fi
            else
                status="DEAD (stale PID)"
                rm -f "$pid_file"
            fi
        fi
        
        printf "Port %d: %-20s" "$port" "$status"
        [[ -n "$pid" ]] && printf " (PID: %s)" "$pid"
        echo
    done
    
    echo "==================="
    echo "Summary: $running_count/$total_count proxy instances running"
    
    return 0
}

# Health check and recovery
health_check() {
    log_info "Performing health check..."
    
    local unhealthy_ports=()
    local recovered_count=0
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        local pid_file="$PID_DIR/proxy_${port}.pid"
        
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file" 2>/dev/null || echo "")
            
            # Check if process is running
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                # Check if port is listening
                if ! netstat -ln 2>/dev/null | grep -q ":$port "; then
                    log_warning "Port $port: Process running but not listening"
                    unhealthy_ports+=($port)
                fi
            else
                log_warning "Port $port: Process not running"
                unhealthy_ports+=($port)
            fi
        else
            log_warning "Port $port: No PID file found"
            unhealthy_ports+=($port)
        fi
    done
    
    # Attempt recovery for unhealthy ports
    if [[ ${#unhealthy_ports[@]} -gt 0 ]]; then
        log_warning "Found ${#unhealthy_ports[@]} unhealthy proxy instances"
        
        for port in "${unhealthy_ports[@]}"; do
            log_info "Attempting to recover proxy on port $port"
            stop_proxy_instance "$port"
            sleep 1
            
            if start_proxy_instance "$port"; then
                ((recovered_count++))
                log_success "Recovered proxy on port $port"
            else
                log_error "Failed to recover proxy on port $port"
            fi
        done
        
        log_info "Recovery complete: $recovered_count/${#unhealthy_ports[@]} instances recovered"
    else
        log_success "All proxy instances are healthy"
    fi
    
    return 0
}

# Main execution
main() {
    acquire_lock
    init_directories
    
    case "${1:-}" in
        start)
            log_info "Starting Proxy SaaS System"
            check_dependencies || exit 1
            start_all_proxies
            ;;
        stop)
            log_info "Stopping Proxy SaaS System"
            stop_all_proxies
            ;;
        restart)
            log_info "Restarting Proxy SaaS System"
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
            echo "Universal Proxy Manager (Fixed Version)"
            echo "Usage: $0 {start|stop|restart|status|health}"
            echo ""
            echo "Features:"
            echo "  - Works with both free and commercial GoProxy"
            echo "  - Robust error handling and recovery"
            echo "  - Comprehensive logging and monitoring"
            echo "  - Lock-based instance management"
            echo "  - Health check and auto-recovery"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
