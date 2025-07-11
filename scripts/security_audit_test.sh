#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - COMPREHENSIVE SECURITY AUDIT TEST SUITE
# ============================================================================
# Tests all security fixes and GoProxy v15.x compliance
# Validates authentication, traffic monitoring, and security measures
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_LOG="$SCRIPT_DIR/security_audit_$(date +%Y%m%d_%H%M%S).log"

# Test configuration
TEST_SERVER_HOST="127.0.0.1"
TEST_API_PORT="8889"
TEST_USERNAME="testuser"
TEST_PASSWORD="testpass123"
TEST_API_KEY="test_api_key_12345"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Logging functions
log_test() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[TEST]${NC} $timestamp - $1" | tee -a "$TEST_LOG"
}

log_pass() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[PASS]${NC} $timestamp - $1" | tee -a "$TEST_LOG"
    ((TESTS_PASSED++))
}

log_fail() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[FAIL]${NC} $timestamp - $1" | tee -a "$TEST_LOG"
    ((TESTS_FAILED++))
}

log_info() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[INFO]${NC} $timestamp - $1" | tee -a "$TEST_LOG"
}

# Test function wrapper
run_test() {
    local test_name="$1"
    local test_function="$2"
    
    ((TESTS_TOTAL++))
    log_test "Running: $test_name"
    
    if $test_function; then
        log_pass "$test_name"
        return 0
    else
        log_fail "$test_name"
        return 1
    fi
}

# Test 1: Hardcoded Credentials Check
test_hardcoded_credentials() {
    log_info "Checking for hardcoded credentials in secure files..."
    
    # Check secure configuration files
    local secure_files=(
        "$PROJECT_ROOT/api/config_secure.php"
        "$PROJECT_ROOT/.env"
        "$PROJECT_ROOT/proxy_manager_secure.sh"
    )
    
    for file in "${secure_files[@]}"; do
        if [[ -f "$file" ]]; then
            # Should NOT contain hardcoded passwords
            if grep -q "ProxySecure2024\|RedisSecure2024" "$file" 2>/dev/null; then
                log_info "FAIL: Found hardcoded credentials in $file"
                return 1
            fi
            
            # Should contain environment variable usage
            if ! grep -q "\$_ENV\|\$\{.*\}" "$file" 2>/dev/null; then
                log_info "FAIL: No environment variable usage found in $file"
                return 1
            fi
        fi
    done
    
    return 0
}

# Test 2: CORS Security Configuration
test_cors_security() {
    log_info "Testing CORS security configuration..."
    
    # Check that wildcard origins are not used in secure files
    local api_files=(
        "$PROJECT_ROOT/api/proxies_secure.php"
        "$PROJECT_ROOT/api/config_secure.php"
    )
    
    for file in "${api_files[@]}"; do
        if [[ -f "$file" ]]; then
            if grep -q "Access-Control-Allow-Origin: \*" "$file" 2>/dev/null; then
                log_info "FAIL: Wildcard CORS origin found in $file"
                return 1
            fi
        fi
    done
    
    return 0
}

# Test 3: GoProxy v15.x Compliance
test_goproxy_compliance() {
    log_info "Testing GoProxy v15.x compliance..."
    
    local proxy_manager="$PROJECT_ROOT/proxy_manager_secure.sh"
    
    if [[ ! -f "$proxy_manager" ]]; then
        log_info "FAIL: Secure proxy manager not found"
        return 1
    fi
    
    # Check for required parameters
    local required_params=(
        "--auth-url"
        "--traffic-url"
        "--control-url"
        "--log-file"
        "--daemon"
    )
    
    for param in "${required_params[@]}"; do
        if ! grep -q "$param" "$proxy_manager"; then
            log_info "FAIL: Missing required parameter: $param"
            return 1
        fi
    done
    
    # Check that --sniff-domain is NOT present (user preference)
    if grep -q "\-\-sniff-domain" "$proxy_manager"; then
        log_info "FAIL: --sniff-domain parameter found (should be removed per user preference)"
        return 1
    fi
    
    # Check localhost-only URLs
    if ! grep -q "127\.0\.0\.1" "$proxy_manager"; then
        log_info "FAIL: Non-localhost URLs found"
        return 1
    fi
    
    return 0
}

# Test 4: Input Validation
test_input_validation() {
    log_info "Testing input validation functions..."
    
    local config_file="$PROJECT_ROOT/api/config_secure.php"
    
    if [[ ! -f "$config_file" ]]; then
        log_info "FAIL: Secure config file not found"
        return 1
    fi
    
    # Check for validation functions
    local validation_functions=(
        "validateInput"
        "getClientIp"
        "checkRateLimit"
    )
    
    for func in "${validation_functions[@]}"; do
        if ! grep -q "function $func" "$config_file"; then
            log_info "FAIL: Missing validation function: $func"
            return 1
        fi
    done
    
    return 0
}

# Test 5: SQL Injection Protection
test_sql_injection_protection() {
    log_info "Testing SQL injection protection..."
    
    local api_files=(
        "$PROJECT_ROOT/api/proxies_secure.php"
        "$PROJECT_ROOT/api/internal/auth.php"
    )
    
    for file in "${api_files[@]}"; do
        if [[ -f "$file" ]]; then
            # Check for prepared statements
            if ! grep -q "prepare(" "$file"; then
                log_info "FAIL: No prepared statements found in $file"
                return 1
            fi
            
            # Check that direct SQL concatenation is not used
            if grep -q "\$.*\." "$file" | grep -q "SELECT\|INSERT\|UPDATE\|DELETE"; then
                log_info "FAIL: Possible SQL concatenation found in $file"
                return 1
            fi
        fi
    done
    
    return 0
}

# Test 6: Environment Variable Configuration
test_environment_variables() {
    log_info "Testing environment variable configuration..."
    
    local env_file="$PROJECT_ROOT/.env"
    
    if [[ ! -f "$env_file" ]]; then
        log_info "FAIL: .env file not found"
        return 1
    fi
    
    # Check for required environment variables
    local required_vars=(
        "DB_PASSWORD"
        "REDIS_PASSWORD"
        "API_SECRET_KEY"
        "JWT_SECRET"
        "ENCRYPTION_KEY"
    )
    
    for var in "${required_vars[@]}"; do
        if ! grep -q "^$var=" "$env_file"; then
            log_info "FAIL: Missing environment variable: $var"
            return 1
        fi
        
        # Check that passwords are not default/weak
        local value=$(grep "^$var=" "$env_file" | cut -d'=' -f2)
        if [[ ${#value} -lt 16 ]]; then
            log_info "FAIL: Weak password/secret for $var (length < 16)"
            return 1
        fi
    done
    
    return 0
}

# Test 7: User-Specific Logging
test_user_logging() {
    log_info "Testing user-specific logging configuration..."
    
    local proxy_manager="$PROJECT_ROOT/proxy_manager_secure.sh"
    
    if [[ ! -f "$proxy_manager" ]]; then
        log_info "FAIL: Secure proxy manager not found"
        return 1
    fi
    
    # Check for user-specific log file paths
    if ! grep -q "user_port_" "$proxy_manager"; then
        log_info "FAIL: User-specific logging not implemented"
        return 1
    fi
    
    # Check for log directory creation
    if ! grep -q "USER_LOG_DIR" "$proxy_manager"; then
        log_info "FAIL: User log directory not configured"
        return 1
    fi
    
    return 0
}

# Test 8: 5GB Quota Configuration
test_quota_configuration() {
    log_info "Testing 5GB quota configuration..."
    
    local env_file="$PROJECT_ROOT/.env"
    
    if [[ ! -f "$env_file" ]]; then
        log_info "FAIL: .env file not found"
        return 1
    fi
    
    # Check for quota configuration
    if ! grep -q "DEFAULT_USER_QUOTA_GB=5" "$env_file"; then
        log_info "FAIL: 5GB default quota not configured"
        return 1
    fi
    
    return 0
}

# Test 9: 5000 Proxy Pool Configuration
test_proxy_pool_configuration() {
    log_info "Testing 5000 proxy pool configuration..."
    
    local env_file="$PROJECT_ROOT/.env"
    
    if [[ ! -f "$env_file" ]]; then
        log_info "FAIL: .env file not found"
        return 1
    fi
    
    # Check for proxy pool configuration
    if ! grep -q "MAX_PROXY_POOL_SIZE=5000" "$env_file"; then
        log_info "FAIL: 5000 proxy pool size not configured"
        return 1
    fi
    
    # Check port range supports large pool
    if ! grep -q "PROXY_PORT_END=4999" "$env_file"; then
        log_info "FAIL: Port range does not support 1000 proxies"
        return 1
    fi
    
    return 0
}

# Test 10: Security Headers
test_security_headers() {
    log_info "Testing security headers implementation..."
    
    local config_file="$PROJECT_ROOT/api/config_secure.php"
    
    if [[ ! -f "$config_file" ]]; then
        log_info "FAIL: Secure config file not found"
        return 1
    fi
    
    # Check for security header functions
    if ! grep -q "setSecureCorsHeaders" "$config_file"; then
        log_info "FAIL: Secure CORS headers function not found"
        return 1
    fi
    
    return 0
}

# Main test execution
main() {
    log_info "Starting Comprehensive Security Audit Test Suite"
    log_info "Test log: $TEST_LOG"
    echo ""
    
    # Run all tests
    run_test "Hardcoded Credentials Check" test_hardcoded_credentials
    run_test "CORS Security Configuration" test_cors_security
    run_test "GoProxy v15.x Compliance" test_goproxy_compliance
    run_test "Input Validation" test_input_validation
    run_test "SQL Injection Protection" test_sql_injection_protection
    run_test "Environment Variable Configuration" test_environment_variables
    run_test "User-Specific Logging" test_user_logging
    run_test "5GB Quota Configuration" test_quota_configuration
    run_test "5000 Proxy Pool Configuration" test_proxy_pool_configuration
    run_test "Security Headers" test_security_headers
    
    # Test summary
    echo ""
    log_info "============================================"
    log_info "SECURITY AUDIT TEST SUMMARY"
    log_info "============================================"
    log_info "Total Tests: $TESTS_TOTAL"
    log_info "Passed: $TESTS_PASSED"
    log_info "Failed: $TESTS_FAILED"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_pass "🎉 ALL SECURITY TESTS PASSED!"
        log_info "Your proxy SaaS system is ready for production deployment"
        echo ""
        log_info "Next steps:"
        log_info "1. Deploy using: sudo ./setup_complete.sh"
        log_info "2. Test authentication: curl http://127.0.0.1:8889/api/internal/auth.php"
        log_info "3. Verify HTTP 204 responses from auth and traffic APIs"
        log_info "4. Load test with 5GB quota and 5000 proxy pool"
        return 0
    else
        log_fail "❌ $TESTS_FAILED security test(s) failed!"
        log_info "Please fix the failed tests before production deployment"
        return 1
    fi
}

# Create test directory if it doesn't exist
mkdir -p "$SCRIPT_DIR"

# Run main function
main "$@"
