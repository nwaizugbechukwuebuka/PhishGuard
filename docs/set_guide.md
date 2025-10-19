# PhishGuard Setup and Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying PhishGuard in production and development environments. PhishGuard supports multiple deployment methods including Docker Compose, Kubernetes, and manual installation.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Configuration](#configuration)
4. [Deployment Methods](#deployment-methods)
5. [Post-Deployment Setup](#post-deployment-setup)
6. [Monitoring and Maintenance](#monitoring-and-maintenance)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

**Minimum Requirements:**
- CPU: 4 cores
- RAM: 8 GB
- Storage: 100 GB SSD
- Network: 1 Gbps

**Recommended for Production:**
- CPU: 8+ cores
- RAM: 16+ GB
- Storage: 500+ GB SSD
- Network: 10 Gbps

### Software Dependencies

- **Container Platform**: Docker 20.10+ and Docker Compose 2.0+
- **Orchestration**: Kubernetes 1.24+ (for K8s deployment)
- **Database**: PostgreSQL 13+
- **Cache**: Redis 6.0+
- **Python**: 3.9+ (for manual installation)
- **Node.js**: 16+ (for frontend development)

### External Services

- **Email Platforms**: Gmail API, Microsoft 365 (optional)
- **Monitoring**: Prometheus, Grafana (recommended)
- **Load Balancer**: nginx, HAProxy, or cloud LB
- **SSL/TLS**: Valid SSL certificates

## Environment Setup

### 1. Clone Repository

```bash
git clone https://github.com/your-org/phishguard.git
cd phishguard
```

### 2. Environment Configuration

Create environment file:

```bash
cp .env.example .env
```

Edit `.env` file with your configuration:

```bash
# Application Settings
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO
SECRET_KEY=your-super-secret-key-change-this

# Database Configuration
DATABASE_HOST=postgres
DATABASE_PORT=5432
DATABASE_NAME=phishguard
DATABASE_USER=phishguard
DATABASE_PASSWORD=secure_password_here

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=redis_password_here

# Security Settings
JWT_SECRET_KEY=jwt-secret-key-change-this
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
ENCRYPTION_KEY=encryption-key-change-this

# Email Integration (Optional)
GMAIL_CLIENT_ID=your-gmail-client-id
GMAIL_CLIENT_SECRET=your-gmail-client-secret
MICROSOFT365_CLIENT_ID=your-ms365-client-id
MICROSOFT365_CLIENT_SECRET=your-ms365-client-secret
MICROSOFT365_TENANT_ID=your-tenant-id

# Notification Settings
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=notifications@example.com
SMTP_PASSWORD=smtp_password

# Monitoring
METRICS_ENABLED=true
METRICS_PORT=8090
HEALTH_CHECK_INTERVAL=30
```

### 3. SSL/TLS Setup

For production deployment, configure SSL certificates:

```bash
# Create SSL directory
mkdir -p ssl

# Copy your SSL certificates
cp your-domain.crt ssl/
cp your-domain.key ssl/
cp ca-bundle.crt ssl/

# Or use Let's Encrypt
certbot certonly --standalone -d your-domain.com
```

## Configuration

### Database Configuration

Create database initialization script:

```sql
-- Create database and user
CREATE DATABASE phishguard;
CREATE USER phishguard WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE phishguard TO phishguard;

-- Enable required extensions
\c phishguard;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
```

### Redis Configuration

Create Redis configuration file (`redis.conf`):

```conf
# Basic Redis configuration for PhishGuard
bind 0.0.0.0
port 6379
requirepass redis_password_here

# Memory management
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000

# Security
protected-mode yes
tcp-keepalive 300

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
```

### Application Configuration

Configure application settings in `src/api/utils/config.py`:

```python
import os
from typing import Optional

class Settings:
    # Application
    APP_NAME: str = "PhishGuard"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Database
    DATABASE_URL: str = (
        f"postgresql://{os.getenv('DATABASE_USER')}:"
        f"{os.getenv('DATABASE_PASSWORD')}@"
        f"{os.getenv('DATABASE_HOST')}:"
        f"{os.getenv('DATABASE_PORT')}/"
        f"{os.getenv('DATABASE_NAME')}"
    )
    
    # Redis
    REDIS_URL: str = (
        f"redis://:{os.getenv('REDIS_PASSWORD')}@"
        f"{os.getenv('REDIS_HOST')}:"
        f"{os.getenv('REDIS_PORT')}/"
        f"{os.getenv('REDIS_DB')}"
    )
    
    # Security
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY")
    
    # Integrations
    GMAIL_CLIENT_ID: Optional[str] = os.getenv("GMAIL_CLIENT_ID")
    SLACK_WEBHOOK_URL: Optional[str] = os.getenv("SLACK_WEBHOOK_URL")

settings = Settings()
```

## Deployment Methods

### Method 1: Docker Compose (Recommended for Development)

#### 1. Build and Start Services

```bash
# Build all services
docker-compose build

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

#### 2. Initialize Database

```bash
# Run database migrations
docker-compose exec backend python -m alembic upgrade head

# Create admin user
docker-compose exec backend python scripts/create_admin.py
```

#### 3. Verify Deployment

```bash
# Check service status
docker-compose ps

# Test API health
curl http://localhost:8000/health

# Access web interface
open http://localhost:3000
```

### Method 2: Kubernetes (Recommended for Production)

#### 1. Prepare Kubernetes Cluster

```bash
# Verify cluster access
kubectl cluster-info

# Create namespace
kubectl create namespace phishguard

# Set default namespace
kubectl config set-context --current --namespace=phishguard
```

#### 2. Configure Secrets

```bash
# Create secrets
kubectl create secret generic phishguard-secrets \
  --from-literal=database-password='secure_password' \
  --from-literal=jwt-secret-key='jwt-secret-key' \
  --from-literal=encryption-key='encryption-key'

# Create TLS secret (for HTTPS)
kubectl create secret tls phishguard-tls \
  --cert=ssl/your-domain.crt \
  --key=ssl/your-domain.key
```

#### 3. Deploy Applications

```bash
# Apply configurations
kubectl apply -f deployment/k8s/configmap.yaml
kubectl apply -f deployment/k8s/deployment.yaml
kubectl apply -f deployment/k8s/service.yaml
kubectl apply -f deployment/k8s/ingress.yaml

# Wait for deployments
kubectl rollout status deployment/phishguard-backend
kubectl rollout status deployment/phishguard-frontend
```

#### 4. Initialize Database

```bash
# Run migrations
kubectl exec -it deployment/phishguard-backend -- python -m alembic upgrade head

# Create admin user
kubectl exec -it deployment/phishguard-backend -- python scripts/create_admin.py
```

### Method 3: Manual Installation

#### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3.9 python3.9-venv python3.9-dev \
  postgresql-client redis-tools nginx supervisor
```

**CentOS/RHEL:**
```bash
sudo yum install -y python39 python39-devel \
  postgresql-client redis nginx supervisor
```

#### 2. Setup Python Environment

```bash
# Create virtual environment
python3.9 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

#### 3. Setup Frontend

```bash
cd src/frontend

# Install Node.js dependencies
npm install

# Build for production
npm run build

# Copy to web server
sudo cp -r build/* /var/www/html/
```

#### 4. Configure Services

**Systemd service for backend:**

```ini
# /etc/systemd/system/phishguard-backend.service
[Unit]
Description=PhishGuard Backend
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=phishguard
Group=phishguard
WorkingDirectory=/opt/phishguard
Environment=PATH=/opt/phishguard/venv/bin
ExecStart=/opt/phishguard/venv/bin/gunicorn -c deployment/gunicorn.conf.py src.api.main:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

**Systemd service for Celery worker:**

```ini
# /etc/systemd/system/phishguard-worker.service
[Unit]
Description=PhishGuard Celery Worker
After=network.target redis.service

[Service]
Type=exec
User=phishguard
Group=phishguard
WorkingDirectory=/opt/phishguard
Environment=PATH=/opt/phishguard/venv/bin
ExecStart=/opt/phishguard/venv/bin/celery -A src.tasks.scan_tasks worker --loglevel=info
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

#### 5. Configure nginx

```nginx
# /etc/nginx/sites-available/phishguard
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/ssl/your-domain.crt;
    ssl_certificate_key /path/to/ssl/your-domain.key;

    # Frontend
    location / {
        root /var/www/html;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 6. Start Services

```bash
# Enable and start services
sudo systemctl enable phishguard-backend phishguard-worker
sudo systemctl start phishguard-backend phishguard-worker

# Enable and restart nginx
sudo systemctl enable nginx
sudo systemctl restart nginx

# Check service status
sudo systemctl status phishguard-backend phishguard-worker nginx
```

## Post-Deployment Setup

### 1. Create Admin User

```bash
# Using the admin creation script
python scripts/create_admin.py \
  --username admin \
  --email admin@your-domain.com \
  --password 'secure_admin_password'
```

### 2. Configure Email Integrations

#### Gmail Integration

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Gmail API
4. Create OAuth 2.0 credentials
5. Download credentials JSON file
6. Upload to PhishGuard configuration

#### Microsoft 365 Integration

1. Go to [Azure Portal](https://portal.azure.com/)
2. Register new application in Azure AD
3. Configure API permissions for Microsoft Graph
4. Generate client secret
5. Configure in PhishGuard settings

### 3. Setup Monitoring

#### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'phishguard'
    static_configs:
      - targets: ['localhost:8090']
    metrics_path: '/metrics'
```

#### Grafana Dashboard

Import PhishGuard dashboard:

```bash
# Import dashboard JSON
curl -X POST \
  http://grafana:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d @monitoring/grafana-dashboard.json
```

### 4. Security Hardening

#### Database Security

```sql
-- Restrict database access
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO phishguard;

-- Enable row level security
ALTER TABLE emails ENABLE ROW LEVEL SECURITY;
CREATE POLICY email_user_policy ON emails
  FOR ALL TO phishguard
  USING (user_id = current_setting('app.current_user_id'));
```

#### Application Security

```bash
# Set secure file permissions
chmod 600 .env
chmod 700 ssl/
chown -R phishguard:phishguard /opt/phishguard

# Configure firewall
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp
sudo ufw --force enable
```

## Monitoring and Maintenance

### Health Checks

Configure health check endpoints:

```yaml
# docker-compose.yml health checks
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 60s
```

### Backup Strategy

#### Database Backup

```bash
#!/bin/bash
# backup-database.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/database"
DB_NAME="phishguard"

# Create backup
pg_dump -h localhost -U phishguard -d $DB_NAME | \
  gzip > "$BACKUP_DIR/phishguard_$DATE.sql.gz"

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
```

#### Application Backup

```bash
#!/bin/bash
# backup-application.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/application"

# Backup quarantine storage
tar -czf "$BACKUP_DIR/quarantine_$DATE.tar.gz" \
  /opt/phishguard/quarantine_storage/

# Backup configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" \
  /opt/phishguard/.env \
  /opt/phishguard/ssl/
```

### Log Management

#### Centralized Logging

```yaml
# docker-compose.yml logging
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

#### Log Rotation

```bash
# /etc/logrotate.d/phishguard
/var/log/phishguard/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
```

### Performance Monitoring

#### Database Performance

```sql
-- Monitor slow queries
SELECT query, mean_time, calls, total_time
FROM pg_stat_statements
WHERE mean_time > 100
ORDER BY mean_time DESC;

-- Check connection usage
SELECT count(*) as connections,
       state,
       application_name
FROM pg_stat_activity
GROUP BY state, application_name;
```

#### Application Performance

```bash
# Monitor resource usage
htop
iotop
netstat -tulpn

# Check service status
systemctl status phishguard-backend
systemctl status phishguard-worker
```

## Troubleshooting

### Common Issues

#### Database Connection Issues

```bash
# Check database connectivity
psql -h localhost -U phishguard -d phishguard -c "SELECT 1;"

# Check connection limits
SELECT setting FROM pg_settings WHERE name = 'max_connections';

# View active connections
SELECT count(*) FROM pg_stat_activity;
```

#### Redis Connection Issues

```bash
# Test Redis connectivity
redis-cli -h localhost -p 6379 ping

# Check Redis memory usage
redis-cli info memory

# Monitor Redis operations
redis-cli monitor
```

#### API Issues

```bash
# Check API logs
docker-compose logs backend

# Test API endpoints
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:8000/api/health

# Check worker status
celery -A src.tasks.scan_tasks inspect active
```

### Log Analysis

#### Application Logs

```bash
# Search for errors
grep -i error /var/log/phishguard/app.log

# Monitor real-time logs
tail -f /var/log/phishguard/app.log

# Analyze performance logs
grep "duration" /var/log/phishguard/app.log | \
  awk '{print $NF}' | sort -n
```

#### Database Logs

```bash
# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-13-main.log

# Search for slow queries
grep "duration" /var/log/postgresql/postgresql-13-main.log
```

### Performance Tuning

#### Database Optimization

```sql
-- Update table statistics
ANALYZE;

-- Reindex tables
REINDEX DATABASE phishguard;

-- Check for unused indexes
SELECT schemaname, tablename, attname, n_distinct, correlation
FROM pg_stats
WHERE schemaname = 'public';
```

#### Application Optimization

```bash
# Increase worker processes
export WORKERS=4
gunicorn -w $WORKERS -c deployment/gunicorn.conf.py src.api.main:app

# Optimize Celery workers
celery -A src.tasks.scan_tasks worker \
  --concurrency=4 \
  --prefetch-multiplier=1
```

### Support and Documentation

For additional support:

- **Documentation**: [https://docs.phishguard.your-domain.com](https://docs.phishguard.your-domain.com)
- **GitHub Issues**: [https://github.com/your-org/phishguard/issues](https://github.com/your-org/phishguard/issues)
- **Support Email**: support@phishguard.your-domain.com
- **Community Forum**: [https://community.phishguard.your-domain.com](https://community.phishguard.your-domain.com)

## Conclusion

This deployment guide provides comprehensive instructions for setting up PhishGuard in various environments. Follow the appropriate method based on your infrastructure requirements and ensure proper monitoring and maintenance for optimal performance.

For production deployments, always use HTTPS, implement proper backup strategies, and follow security best practices. Regular updates and monitoring are essential for maintaining a secure and efficient PhishGuard installation.
