# PROXY-SAAS-SYSTEM - COMPLETE INSTALLATION GUIDE

## 🚀 **PRODUCTION-READY INSTALLATION**

This guide provides step-by-step instructions for installing the completely fixed Proxy SaaS System.

## **📋 SYSTEM REQUIREMENTS**

### **Minimum Requirements:**
- **OS:** Ubuntu 20.04+ / Debian 10+ / CentOS 8+
- **RAM:** 2GB (4GB recommended for production)
- **Disk:** 5GB free space
- **CPU:** 2 cores (4+ recommended for production)
- **Network:** Internet connection for installation

### **Supported Operating Systems:**
- ✅ Ubuntu 22.04 LTS (Recommended)
- ✅ Ubuntu 20.04 LTS
- ✅ Debian 11
- ✅ Debian 10
- ⚠️ CentOS 8+ (Experimental)
- ⚠️ RHEL 8+ (Experimental)

## **🎯 QUICK INSTALLATION (RECOMMENDED)**

### **One-Command Installation:**
```bash
# Download the fixed version
git clone https://github.com/your-repo/proxy-saas-fixed.git
cd proxy-saas-fixed

# Make executable and run
chmod +x setup_complete.sh
sudo ./setup_complete.sh
```

**That's it!** The script will automatically:
- Install all dependencies
- Setup database and Redis
- Configure web server
- Install and configure GoProxy
- Create systemd service
- Test the installation

## **📝 MANUAL INSTALLATION (ADVANCED)**

If you prefer manual installation or need to customize the setup:

### **Step 1: Prepare System**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install basic tools
sudo apt install -y curl wget git unzip
```

### **Step 2: Install Dependencies**
```bash
# Install web server and PHP
sudo apt install -y nginx php8.1 php8.1-fpm php8.1-mysql php8.1-redis php8.1-curl php8.1-mbstring php8.1-xml

# Install database and cache
sudo apt install -y mariadb-server mariadb-client redis-server

# Install system tools
sudo apt install -y net-tools bc jq htop nano vim
```

### **Step 3: Install GoProxy**
```bash
# Download and install GoProxy
wget https://github.com/snail007/goproxy/releases/download/v15.1/proxy-linux-amd64.tar.gz
tar -xzf proxy-linux-amd64.tar.gz
sudo mv proxy /usr/local/bin/
sudo chmod +x /usr/local/bin/proxy
```

### **Step 4: Setup Database**
```bash
# Start MariaDB
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Secure installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -u root -p << EOF
CREATE DATABASE proxy_saas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'proxy_user'@'localhost' IDENTIFIED BY 'ProxySecure2024!';
GRANT ALL PRIVILEGES ON proxy_saas.* TO 'proxy_user'@'localhost';
FLUSH PRIVILEGES;
EOF
```

### **Step 5: Setup Redis**
```bash
# Configure Redis
sudo sed -i 's/^# requirepass.*/requirepass RedisSecure2024!/' /etc/redis/redis.conf

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

### **Step 6: Setup Project Files**
```bash
# Create directories
sudo mkdir -p /opt/proxy-saas-system/{config,logs,pids,database}
sudo mkdir -p /var/www/html/api/internal

# Create service user
sudo useradd -r -s /bin/bash -d /opt/proxy-saas-system proxy-saas

# Copy files
sudo cp proxy_manager.sh /opt/proxy-saas-system/
sudo cp api/config.php /var/www/html/api/
sudo cp api/proxies.php /var/www/html/api/
sudo cp api/internal/auth.php /var/www/html/api/internal/
sudo cp database/schema.sql /opt/proxy-saas-system/database/

# Set permissions
sudo chown -R proxy-saas:proxy-saas /opt/proxy-saas-system
sudo chown -R www-data:www-data /var/www/html
sudo chmod +x /opt/proxy-saas-system/proxy_manager.sh
```

### **Step 7: Import Database Schema**
```bash
# Import schema
sudo mysql -u root -p proxy_saas < /opt/proxy-saas-system/database/schema.sql
```

### **Step 8: Configure Nginx**
```bash
# Create Nginx configuration
sudo tee /etc/nginx/sites-available/proxy-saas-system << EOF
server {
    listen 8889;
    server_name $(curl -s ifconfig.me);
    root /var/www/html;
    index index.php index.html;
    
    location /api/ {
        try_files \$uri \$uri/ /api/proxies.php?\$query_string;
        
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
    }
    
    location ~ /\. {
        deny all;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/proxy-saas-system /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### **Step 9: Create Systemd Service**
```bash
# Create service file
sudo tee /etc/systemd/system/proxy-saas-system.service << EOF
[Unit]
Description=Proxy SaaS System - Fixed Proxy Manager
After=network.target mariadb.service redis-server.service
Wants=mariadb.service redis-server.service

[Service]
Type=forking
User=proxy-saas
Group=proxy-saas
WorkingDirectory=/opt/proxy-saas-system
ExecStart=/opt/proxy-saas-system/proxy_manager.sh start
ExecStop=/opt/proxy-saas-system/proxy_manager.sh stop
ExecReload=/opt/proxy-saas-system/proxy_manager.sh restart
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable proxy-saas-system
sudo systemctl start proxy-saas-system
```

## **🧪 TESTING INSTALLATION**

### **1. Check Service Status**
```bash
# Check all services
sudo systemctl status proxy-saas-system mariadb redis-server nginx php8.1-fpm

# Check proxy manager status
sudo -u proxy-saas /opt/proxy-saas-system/proxy_manager.sh status
```

### **2. Test Database Connection**
```bash
# Test database
mysql -u proxy_user -p'ProxySecure2024!' proxy_saas -e "SELECT COUNT(*) FROM users;"
```

### **3. Test API Endpoints**
```bash
# Get server IP
SERVER_IP=$(curl -s ifconfig.me)

# Test main API
curl "http://$SERVER_IP:8889/api/proxies.php"

# Test health check
curl "http://$SERVER_IP:8889/api/proxies.php?action=health"

# Test proxy status
curl "http://$SERVER_IP:8889/api/proxies.php?action=status"
```

### **4. Test Proxy Functionality**
```bash
# Test individual proxies
curl -x http://127.0.0.1:4000 http://httpbin.org/ip
curl -x http://127.0.0.1:4001 http://httpbin.org/ip

# Test all proxies
for port in {4000..4010}; do
    echo "Testing port $port:"
    curl -x http://127.0.0.1:$port http://httpbin.org/ip --connect-timeout 5 || echo "Port $port failed"
done
```

## **🔧 CONFIGURATION**

### **Default Configuration:**
- **Database:** `proxy_saas` with user `proxy_user`
- **Redis:** Password `RedisSecure2024!`
- **Proxy Ports:** 4000-4010 (11 instances)
- **API Port:** 8889
- **Service User:** proxy-saas

### **Customization:**
Edit the configuration files:
- **Database:** `/var/www/html/api/config.php`
- **Proxy Manager:** `/opt/proxy-saas-system/proxy_manager.sh`
- **Nginx:** `/etc/nginx/sites-available/proxy-saas-system`

## **📊 MONITORING**

### **Service Logs:**
```bash
# System service logs
sudo journalctl -u proxy-saas-system -f

# Proxy manager logs
sudo tail -f /opt/proxy-saas-system/logs/manager.log

# API logs
sudo tail -f /var/log/proxy-saas-system/api.log

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### **Health Monitoring:**
```bash
# Check proxy health
sudo -u proxy-saas /opt/proxy-saas-system/proxy_manager.sh health

# API health check
curl "http://$(curl -s ifconfig.me):8889/api/proxies.php?action=health"
```

## **🛠️ TROUBLESHOOTING**

### **Common Issues:**

#### **1. Service Won't Start**
```bash
# Check service status
sudo systemctl status proxy-saas-system

# Check logs
sudo journalctl -u proxy-saas-system -n 50

# Check GoProxy installation
proxy --version

# Test proxy manager manually
sudo -u proxy-saas /opt/proxy-saas-system/proxy_manager.sh start
```

#### **2. API Not Responding**
```bash
# Check Nginx status
sudo systemctl status nginx

# Check PHP-FPM status
sudo systemctl status php8.1-fpm

# Test Nginx configuration
sudo nginx -t

# Check API logs
sudo tail -50 /var/log/proxy-saas-system/api.log
```

#### **3. Database Connection Issues**
```bash
# Check MariaDB status
sudo systemctl status mariadb

# Test database connection
mysql -u proxy_user -p'ProxySecure2024!' proxy_saas -e "SHOW TABLES;"

# Check database logs
sudo tail -50 /var/log/mysql/error.log
```

#### **4. Proxy Instances Not Starting**
```bash
# Check GoProxy version
proxy --version

# Test basic proxy command
proxy http -p ":4000" --daemon

# Check port availability
netstat -tlnp | grep :400

# Check proxy manager logs
sudo tail -50 /opt/proxy-saas-system/logs/manager.log
```

## **🔒 SECURITY CONSIDERATIONS**

### **Production Security:**
1. **Change Default Passwords** - Update database and Redis passwords
2. **Firewall Configuration** - Restrict access to necessary ports only
3. **SSL/TLS Setup** - Configure HTTPS for API endpoints
4. **User Authentication** - Implement proper user authentication
5. **Rate Limiting** - Configure appropriate rate limits
6. **Log Monitoring** - Set up log monitoring and alerting

### **Recommended Firewall Rules:**
```bash
# Allow SSH
sudo ufw allow 22

# Allow HTTP/HTTPS
sudo ufw allow 80
sudo ufw allow 443

# Allow API port
sudo ufw allow 8889

# Allow proxy ports (if external access needed)
sudo ufw allow 4000:4010/tcp

# Enable firewall
sudo ufw enable
```

## **📈 PERFORMANCE OPTIMIZATION**

### **For Production Use:**
1. **Increase Proxy Instances** - Modify port range in proxy_manager.sh
2. **Database Optimization** - Tune MariaDB configuration
3. **Redis Optimization** - Configure Redis for performance
4. **Nginx Optimization** - Tune Nginx worker processes
5. **System Resources** - Monitor and scale system resources

### **Scaling:**
- **Horizontal Scaling:** Deploy multiple instances with load balancer
- **Vertical Scaling:** Increase server resources (CPU, RAM, disk)
- **Database Scaling:** Use database clustering or read replicas
- **Proxy Pool Scaling:** Increase proxy instance count

## **✅ SUCCESS INDICATORS**

Your installation is successful when:

✅ All services are running: `sudo systemctl status proxy-saas-system mariadb redis-server nginx`  
✅ API responds: `curl "http://$(curl -s ifconfig.me):8889/api/proxies.php"`  
✅ Proxies are listening: `netstat -tlnp | grep :400`  
✅ Proxy functionality works: `curl -x http://127.0.0.1:4000 http://httpbin.org/ip`  
✅ Database is accessible: `mysql -u proxy_user -p'ProxySecure2024!' proxy_saas -e "SELECT 1;"`  

**Congratulations! Your Proxy SaaS System is now ready for production use!** 🎉
