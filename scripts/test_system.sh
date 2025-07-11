#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - SYSTEM TESTING SCRIPT
# ============================================================================
# 
# Comprehensive testing script to validate system functionality
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
DB_NAME="proxy_saas"
DB_USER="proxy_user"
DB_PASSWORD="ProxySecure2024!"

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
    ((TESTS_TOTAL++))
}

# Get server IP
get_server_ip() {
    curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}' || echo "127.0.0.1"
}

# Test system services
test_services() {
    echo ""
    log_info "Testing system services..."
    
    local services=("mariadb" "redis-server" "nginx" "php8.1-fpm" "$PROJECT_NAME")
    
    for service in "${services[@]}"; do
        log_test "Service: $service"
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log_success "$service is running"
        else
            log_error "$service is not running"
        fi
    done
}

# Test database connectivity
test_database() {
    echo ""
    log_info "Testing database connectivity..."
    
    log_test "Database connection"
    if mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT 1;" >/dev/null 2>&1; then
        log_success "Database connection successful"
    else
        log_error "Database connection failed"
        return
    fi
    
    log_test "Database tables"
    local tables=$(mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SHOW TABLES;" 2>/dev/null | wc -l)
    if [[ $tables -gt 5 ]]; then
        log_success "Database tables exist ($((tables-1)) tables)"
    else
        log_error "Database tables missing"
    fi
    
    log_test "Sample data"
    local users=$(mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT COUNT(*) FROM users;" 2>/dev/null | tail -1)
    if [[ $users -gt 0 ]]; then
        log_success "Sample data exists ($users users)"
    else
        log_error "No sample data found"
    fi
}

# Test Redis connectivity
test_redis() {
    echo ""
    log_info "Testing Redis connectivity..."
    
    log_test "Redis connection"
    if redis-cli -a "RedisSecure2024!" ping >/dev/null 2>&1; then
        log_success "Redis connection successful"
    else
        log_error "Redis connection failed"
    fi
    
    log_test "Redis memory info"
    local memory=$(redis-cli -a "RedisSecure2024!" info memory 2>/dev/null | grep used_memory_human | cut -d: -f2 | tr -d '\r')
    if [[ -n "$memory" ]]; then
        log_success "Redis memory usage: $memory"
    else
        log_error "Cannot get Redis memory info"
    fi
}

# Test GoProxy installation
test_goproxy() {
    echo ""
    log_info "Testing GoProxy installation..."
    
    log_test "GoProxy binary"
    if command -v proxy >/dev/null 2>&1; then
        local version=$(proxy --version 2>&1 | head -1)
        log_success "GoProxy found: $version"
    else
        log_error "GoProxy not found"
        return
    fi
    
    log_test "GoProxy capabilities"
    if proxy http --help 2>&1 | grep -q "log-file"; then
        log_success "Commercial GoProxy features detected"
    else
        log_success "Free GoProxy version detected"
    fi
}

# Test proxy instances
test_proxy_instances() {
    echo ""
    log_info "Testing proxy instances..."
    
    local running_count=0
    local listening_count=0
    
    for port in {4000..4010}; do
        log_test "Proxy port $port"
        
        # Check if process is running
        local pid_file="$INSTALL_DIR/pids/proxy_${port}.pid"
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file" 2>/dev/null || echo "")
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                ((running_count++))
                
                # Check if port is listening
                if netstat -ln 2>/dev/null | grep -q ":$port "; then
                    ((listening_count++))
                    log_success "Port $port: Running and listening (PID: $pid)"
                else
                    log_error "Port $port: Running but not listening (PID: $pid)"
                fi
            else
                log_error "Port $port: Dead process (stale PID file)"
            fi
        else
            log_error "Port $port: Not running (no PID file)"
        fi
    done
    
    echo ""
    log_info "Proxy summary: $running_count running, $listening_count listening"
}

# Test API endpoints
test_api() {
    echo ""
    log_info "Testing API endpoints..."
    
    local server_ip=$(get_server_ip)
    local base_url="http://$server_ip:8889/api"
    
    log_test "API base endpoint"
    if curl -s "$base_url/proxies.php" >/dev/null 2>&1; then
        log_success "API base endpoint accessible"
    else
        log_error "API base endpoint not accessible"
        return
    fi
    
    log_test "API proxy list"
    local response=$(curl -s "$base_url/proxies.php" 2>/dev/null)
    if echo "$response" | jq -e '.data.proxies' >/dev/null 2>&1; then
        local proxy_count=$(echo "$response" | jq -r '.data.total' 2>/dev/null || echo "0")
        log_success "API proxy list working ($proxy_count proxies)"
    else
        log_error "API proxy list not working"
    fi
    
    log_test "API health check"
    local health_response=$(curl -s "$base_url/proxies.php?action=health" 2>/dev/null)
    if echo "$health_response" | jq -e '.status' >/dev/null 2>&1; then
        local status=$(echo "$health_response" | jq -r '.status' 2>/dev/null)
        if [[ "$status" == "healthy" ]]; then
            log_success "API health check: $status"
        else
            log_warning "API health check: $status"
        fi
    else
        log_error "API health check not working"
    fi
    
    log_test "API status endpoint"
    if curl -s "$base_url/proxies.php?action=status" >/dev/null 2>&1; then
        log_success "API status endpoint working"
    else
        log_error "API status endpoint not working"
    fi
}

# Test proxy functionality
test_proxy_functionality() {
    echo ""
    log_info "Testing proxy functionality..."
    
    local working_proxies=0
    local test_url="http://httpbin.org/ip"
    
    for port in {4000..4002}; do  # Test first 3 proxies
        log_test "Proxy functionality on port $port"
        
        if netstat -ln 2>/dev/null | grep -q ":$port "; then
            local result=$(curl -x "http://127.0.0.1:$port" "$test_url" --connect-timeout 10 --max-time 15 2>/dev/null || echo "")
            
            if [[ -n "$result" ]] && echo "$result" | jq -e '.origin' >/dev/null 2>&1; then
                local origin_ip=$(echo "$result" | jq -r '.origin' 2>/dev/null)
                log_success "Port $port: Working (Origin IP: $origin_ip)"
                ((working_proxies++))
            else
                log_error "Port $port: Not working (no response or invalid JSON)"
            fi
        else
            log_error "Port $port: Not listening"
        fi
    done
    
    echo ""
    log_info "Proxy functionality summary: $working_proxies/3 proxies working"
}

# Test file permissions
test_permissions() {
    echo ""
    log_info "Testing file permissions..."
    
    log_test "Installation directory ownership"
    if [[ $(stat -c '%U' "$INSTALL_DIR" 2>/dev/null) == "proxy-saas" ]]; then
        log_success "Installation directory owned by proxy-saas"
    else
        log_error "Installation directory not owned by proxy-saas"
    fi
    
    log_test "Proxy manager executable"
    if [[ -x "$INSTALL_DIR/proxy_manager.sh" ]]; then
        log_success "Proxy manager is executable"
    else
        log_error "Proxy manager is not executable"
    fi
    
    log_test "Log directory writable"
    if sudo -u proxy-saas touch "$INSTALL_DIR/logs/test.log" 2>/dev/null; then
        sudo -u proxy-saas rm -f "$INSTALL_DIR/logs/test.log"
        log_success "Log directory is writable"
    else
        log_error "Log directory is not writable"
    fi
    
    log_test "PID directory writable"
    if sudo -u proxy-saas touch "$INSTALL_DIR/pids/test.pid" 2>/dev/null; then
        sudo -u proxy-saas rm -f "$INSTALL_DIR/pids/test.pid"
        log_success "PID directory is writable"
    else
        log_error "PID directory is not writable"
    fi
}

# Test system resources
test_resources() {
    echo ""
    log_info "Testing system resources..."
    
    log_test "Disk space"
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -lt 90 ]]; then
        log_success "Disk usage: ${disk_usage}% (healthy)"
    else
        log_warning "Disk usage: ${disk_usage}% (high)"
    fi
    
    log_test "Memory usage"
    local memory_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [[ $memory_usage -lt 90 ]]; then
        log_success "Memory usage: ${memory_usage}% (healthy)"
    else
        log_warning "Memory usage: ${memory_usage}% (high)"
    fi
    
    log_test "System load"
    if command -v uptime >/dev/null 2>&1; then
        local load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
        log_success "System load: $load"
    else
        log_warning "Cannot determine system load"
    fi
}

# Generate test report
generate_report() {
    echo ""
    echo "============================================================================"
    echo "SYSTEM TEST REPORT"
    echo "============================================================================"
    echo ""
    echo "Test Summary:"
    echo "  Total Tests: $TESTS_TOTAL"
    echo "  Passed: $TESTS_PASSED"
    echo "  Failed: $TESTS_FAILED"
    echo "  Success Rate: $(( (TESTS_PASSED * 100) / TESTS_TOTAL ))%"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✅ ALL TESTS PASSED - SYSTEM IS HEALTHY${NC}"
        echo ""
        echo "Your Proxy SaaS System is working correctly!"
        echo ""
        local server_ip=$(get_server_ip)
        echo "Quick Access:"
        echo "  API URL: http://$server_ip:8889/api/proxies.php"
        echo "  Health Check: http://$server_ip:8889/api/proxies.php?action=health"
        echo "  Test Proxy: curl -x http://127.0.0.1:4000 http://httpbin.org/ip"
        echo ""
    elif [[ $TESTS_FAILED -le 2 ]]; then
        echo -e "${YELLOW}⚠️  MINOR ISSUES DETECTED${NC}"
        echo ""
        echo "System is mostly functional but has minor issues."
        echo "Check the failed tests above and fix them if needed."
        echo ""
    else
        echo -e "${RED}❌ MAJOR ISSUES DETECTED${NC}"
        echo ""
        echo "System has significant problems that need attention."
        echo "Please review the failed tests and fix the issues."
        echo ""
        echo "Common fixes:"
        echo "  - Restart services: sudo systemctl restart proxy-saas-system"
        echo "  - Check logs: sudo journalctl -u proxy-saas-system -n 50"
        echo "  - Verify installation: sudo ./setup_complete.sh"
        echo ""
    fi
    
    echo "============================================================================"
}

# Main function
main() {
    echo "============================================================================"
    echo "PROXY-SAAS-SYSTEM - COMPREHENSIVE SYSTEM TEST"
    echo "============================================================================"
    echo ""
    echo "Testing system functionality and health..."
    echo ""
    
    # Run all tests
    test_services
    test_database
    test_redis
    test_goproxy
    test_proxy_instances
    test_api
    test_proxy_functionality
    test_permissions
    test_resources
    
    # Generate report
    generate_report
    
    # Exit with appropriate code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        exit 0
    elif [[ $TESTS_FAILED -le 2 ]]; then
        exit 1
    else
        exit 2
    fi
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    log_warning "Running as root. Some tests may not reflect actual service user permissions."
fi

# Run main function
main "$@"
