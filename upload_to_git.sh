#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - GIT UPLOAD SCRIPT
# ============================================================================
# Automatically uploads the secure proxy SaaS system to GitHub
# Usage: ./upload_to_git.sh
# ============================================================================

set -euo pipefail

# Configuration
REPO_URL="https://github.com/nixbro/proxy-saas-fixed.git"
BRANCH="main"
COMMIT_MESSAGE="🚀 Secure Proxy SaaS System - Production Ready

✅ SECURITY FIXES APPLIED:
- No hardcoded credentials (all moved to environment variables)
- SQL injection protection with prepared statements
- Input validation and sanitization
- CORS security (no wildcard origins)
- Rate limiting with Redis backend
- XSS prevention with proper output encoding

✅ GOPROXY v15.x COMPLIANCE:
- HTTP 204 response codes for AUTH_URL and TRAFFIC_URL
- User-specific logging with --log-file parameter
- Localhost-only internal APIs (127.0.0.1)
- Removed --sniff-domain parameter
- Always-on authentication and traffic monitoring

✅ ARCHITECTURE FEATURES:
- 5GB user quota system
- 5000 proxy pool capacity (ports 4000-4999)
- No rate limits on IP Management API
- Production-ready .env configuration
- One-line installation script

🧪 COMPREHENSIVE TESTING:
- Security audit test suite included
- GoProxy v15.x compliance verification
- Production deployment checklist
- Performance benchmarking tools

🚀 ONE-LINE INSTALLATION:
curl -sSL https://raw.githubusercontent.com/nixbro/proxy-saas-fixed/main/quick_install.sh | sudo bash"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Banner
echo -e "${GREEN}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║              PROXY SAAS SYSTEM - GIT UPLOAD                 ║
║                 Secure & Compliant Version                  ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if we're in the right directory
if [[ ! -f "quick_install.sh" ]] || [[ ! -f ".env" ]]; then
    log_error "Please run this script from the proxy-saas-fixed directory"
    log_error "Expected files: quick_install.sh, .env"
    exit 1
fi

log_info "🚀 Starting Git upload process..."

# Check if git is installed
if ! command -v git >/dev/null 2>&1; then
    log_error "Git is not installed. Please install git first."
    exit 1
fi

# Check if we're already in a git repository
if [[ ! -d ".git" ]]; then
    log_info "📁 Initializing Git repository..."
    git init
    log_success "Git repository initialized"
else
    log_info "📁 Git repository already exists"
fi

# Add remote origin if it doesn't exist
if ! git remote get-url origin >/dev/null 2>&1; then
    log_info "🔗 Adding remote origin..."
    git remote add origin "$REPO_URL"
    log_success "Remote origin added: $REPO_URL"
else
    log_info "🔗 Remote origin already exists"
    # Update remote URL to ensure it's correct
    git remote set-url origin "$REPO_URL"
    log_info "Remote origin URL updated: $REPO_URL"
fi

# Create .gitignore if it doesn't exist
if [[ ! -f ".gitignore" ]]; then
    log_warning ".gitignore file not found, but it should exist"
fi

# Stage all files
log_info "📦 Staging files for commit..."
git add .

# Check if there are any changes to commit
if git diff --staged --quiet; then
    log_warning "No changes to commit"
    log_info "Repository is already up to date"
else
    log_info "📝 Committing changes..."
    git commit -m "$COMMIT_MESSAGE"
    log_success "Changes committed successfully"
fi

# Check if main branch exists locally
if ! git show-ref --verify --quiet refs/heads/main; then
    log_info "🌿 Creating main branch..."
    git branch -M main
fi

# Push to GitHub
log_info "🚀 Pushing to GitHub..."
if git push -u origin main; then
    log_success "✅ Successfully pushed to GitHub!"
else
    log_error "❌ Failed to push to GitHub"
    log_info "This might be due to authentication issues or network problems"
    log_info "Please check your GitHub credentials and try again"
    exit 1
fi

# Get repository info
REPO_NAME=$(basename "$REPO_URL" .git)
GITHUB_USER=$(echo "$REPO_URL" | sed 's/.*github\.com[:/]\([^/]*\)\/.*/\1/')

echo ""
log_success "🎉 Upload completed successfully!"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    UPLOAD SUCCESSFUL!                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📍 Repository URL:${NC} https://github.com/$GITHUB_USER/$REPO_NAME"
echo -e "${BLUE}🌐 Clone URL:${NC} $REPO_URL"
echo -e "${BLUE}🚀 One-line install:${NC} curl -sSL https://raw.githubusercontent.com/$GITHUB_USER/$REPO_NAME/main/quick_install.sh | sudo bash"
echo ""
echo -e "${YELLOW}📋 NEXT STEPS:${NC}"
echo "1. Visit your GitHub repository to verify the upload"
echo "2. Update repository description and topics"
echo "3. Test the one-line installation command"
echo "4. Share the repository with your team"
echo ""
echo -e "${GREEN}🔐 SECURITY FEATURES INCLUDED:${NC}"
echo "✅ No hardcoded credentials"
echo "✅ SQL injection protection"
echo "✅ GoProxy v15.x compliance"
echo "✅ User-specific logging"
echo "✅ 5GB quota system"
echo "✅ 5000 proxy pool capacity"
echo ""
echo -e "${BLUE}🧪 TEST YOUR DEPLOYMENT:${NC}"
echo "curl -sSL https://raw.githubusercontent.com/$GITHUB_USER/$REPO_NAME/main/quick_install.sh | sudo bash"
echo ""

log_info "📋 Upload process completed successfully!"
