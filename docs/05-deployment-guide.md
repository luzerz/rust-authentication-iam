# Deployment Guide

## Overview

This guide covers deploying the authentication service in various environments, from local development to production. The service supports Docker deployment, environment-specific configurations, and production-ready features.

## Prerequisites

### System Requirements
- **Rust**: 1.88.0 or later
- **PostgreSQL**: 13.0 or later
- **Docker**: 20.10 or later (for containerized deployment)
- **Docker Compose**: 2.0 or later (for local development)

### Network Requirements
- **HTTP Port**: 8080 (configurable)
- **Database Port**: 5432 (PostgreSQL)
- **Health Check Endpoint**: `/health`

## Local Development Setup

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd authentication-service

# Install Rust dependencies
cargo build

# Setup environment variables
cp .env.example .env
```

### 2. Database Setup

#### Using Docker Compose (Recommended)
```bash
# Start PostgreSQL database
docker-compose up -d postgres

# Run database migrations
export DATABASE_URL="postgresql://test_user:test_pass@localhost:5433/test_auth_db"
cargo sqlx migrate run

# Prepare SQLx queries
cargo sqlx prepare
```

#### Using Local PostgreSQL
```bash
# Create database
createdb auth_service

# Run migrations
export DATABASE_URL="postgresql://username:password@localhost:5432/auth_service"
cargo sqlx migrate run
```

### 3. Environment Configuration

Create `.env` file:
```bash
# Database Configuration
DATABASE_URL=postgresql://test_user:test_pass@localhost:5433/test_auth_db

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key-here
JWT_ACCESS_TOKEN_EXPIRY=900
JWT_REFRESH_TOKEN_EXPIRY=604800

# Server Configuration
HTTP_HOST=0.0.0.0
HTTP_PORT=8080

# Password Security
BCRYPT_COST=12

# Account Security
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCK_DURATION=900

# Logging
RUST_LOG=info
RUST_BACKTRACE=1
```

### 4. Run the Service

```bash
# Development mode with hot reload
cargo run

# Or using cargo watch for auto-restart
cargo install cargo-watch
cargo watch -x run
```

### 5. Verify Installation

```bash
# Health check
curl http://localhost:8080/health

# API documentation
open http://localhost:8080/swagger
```

## Docker Deployment

### 1. Development Docker Setup

#### Docker Compose Configuration
```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: test_auth_db
      POSTGRES_USER: test_user
      POSTGRES_PASSWORD: test_pass
    ports:
      - "5433:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U test_user -d test_auth_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  auth-service:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://test_user:test_pass@postgres:5432/test_auth_db
      - JWT_SECRET_KEY=your-super-secret-jwt-key-here
      - RUST_LOG=debug
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - .:/app
      - cargo_cache:/usr/local/cargo/registry
      - target_cache:/app/target
    command: cargo run

volumes:
  postgres_data:
  cargo_cache:
  target_cache:
```

#### Development Dockerfile
```dockerfile
# Dockerfile.dev
FROM rust:1.88-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/authentication_service /app/authentication_service

# Copy migrations
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080

CMD ["./authentication_service"]
```

### 2. Production Docker Setup

#### Production Dockerfile
```dockerfile
# Dockerfile
FROM rust:1.88-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r authuser && useradd -r -g authuser authuser

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/authentication_service /app/authentication_service

# Copy migrations
COPY --from=builder /app/migrations ./migrations

# Change ownership
RUN chown -R authuser:authuser /app

# Switch to non-root user
USER authuser

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["./authentication_service"]
```

#### Production Docker Compose
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: auth_service
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U auth_user -d auth_service"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  auth-service:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - DATABASE_URL=postgresql://auth_user:${DB_PASSWORD}@postgres:5432/auth_service
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - HTTP_HOST=0.0.0.0
      - HTTP_PORT=8080
      - RUST_LOG=info
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    ports:
      - "8080:8080"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - auth-service
    restart: unless-stopped

volumes:
  postgres_data:
```

### 3. Build and Run

```bash
# Development
docker-compose up -d

# Production
docker-compose -f docker-compose.prod.yml up -d

# Build specific image
docker build -t auth-service:latest .

# Run with custom environment
docker run -d \
  --name auth-service \
  -p 8080:8080 \
  -e DATABASE_URL="postgresql://user:pass@host:5432/db" \
  -e JWT_SECRET_KEY="your-secret-key" \
  auth-service:latest
```

## Production Deployment

### 1. Environment Configuration

#### Production Environment Variables
```bash
# Database
DATABASE_URL=postgresql://auth_user:secure_password@db.example.com:5432/auth_service

# JWT Configuration
JWT_SECRET_KEY=your-production-jwt-secret-key-here
JWT_ACCESS_TOKEN_EXPIRY=900
JWT_REFRESH_TOKEN_EXPIRY=604800

# Server Configuration
HTTP_HOST=0.0.0.0
HTTP_PORT=8080

# Security
BCRYPT_COST=12
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCK_DURATION=900

# Logging
RUST_LOG=info
RUST_BACKTRACE=0

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
```

### 2. Database Setup

#### Production PostgreSQL Configuration
```sql
-- Create database and user
CREATE DATABASE auth_service;
CREATE USER auth_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_user;

-- Connect to database
\c auth_service

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO auth_user;
```

#### Run Migrations
```bash
# Set production database URL
export DATABASE_URL="postgresql://auth_user:secure_password@db.example.com:5432/auth_service"

# Run migrations
cargo sqlx migrate run

# Verify migration status
cargo sqlx migrate info
```

### 3. Reverse Proxy Configuration

#### Nginx Configuration
```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream auth_service {
        server auth-service:8080;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;

    server {
        listen 80;
        server_name auth.example.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name auth.example.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

        # Health check endpoint
        location /health {
            proxy_pass http://auth_service;
            access_log off;
        }

        # API endpoints
        location /v1/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://auth_service;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Swagger documentation
        location /swagger {
            proxy_pass http://auth_service;
        }
    }
}
```

### 4. Monitoring and Observability

#### Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service:9090']
    metrics_path: '/metrics'
```

#### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Authentication Service",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])",
            "legendFormat": "5xx errors"
          }
        ]
      }
    ]
  }
}
```

### 5. Security Considerations

#### SSL/TLS Configuration
```bash
# Generate SSL certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem -out ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=auth.example.com"
```

#### Firewall Configuration
```bash
# UFW firewall rules
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 5432/tcp  # PostgreSQL (if external)
ufw enable
```

#### Security Headers
```rust
// Add security headers middleware
use axum::http::HeaderValue;

let app = Router::new()
    .layer(axum::middleware::map_response(|response| async {
        let mut response = response;
        response.headers_mut().insert(
            "X-Frame-Options",
            HeaderValue::from_static("DENY"),
        );
        response.headers_mut().insert(
            "X-Content-Type-Options",
            HeaderValue::from_static("nosniff"),
        );
        response.headers_mut().insert(
            "X-XSS-Protection",
            HeaderValue::from_static("1; mode=block"),
        );
        response
    }));
```

## Kubernetes Deployment

### 1. Namespace and ConfigMap

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth-service

---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
  namespace: auth-service
data:
  DATABASE_URL: "postgresql://auth_user:$(DB_PASSWORD)@postgres-service:5432/auth_service"
  HTTP_HOST: "0.0.0.0"
  HTTP_PORT: "8080"
  RUST_LOG: "info"
```

### 2. Secret

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-service-secret
  namespace: auth-service
type: Opaque
data:
  JWT_SECRET_KEY: <base64-encoded-secret>
  DB_PASSWORD: <base64-encoded-password>
```

### 3. Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: auth-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            configMapKeyRef:
              name: auth-service-config
              key: DATABASE_URL
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: auth-service-secret
              key: JWT_SECRET_KEY
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auth-service-secret
              key: DB_PASSWORD
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

### 4. Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: auth-service
spec:
  selector:
    app: auth-service
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

### 5. Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-service-ingress
  namespace: auth-service
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - auth.example.com
    secretName: auth-service-tls
  rules:
  - host: auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 80
```

## Backup and Recovery

### 1. Database Backup

```bash
# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="auth_service"

# Create backup
pg_dump -h localhost -U auth_user -d $DB_NAME > $BACKUP_DIR/backup_$DATE.sql

# Compress backup
gzip $BACKUP_DIR/backup_$DATE.sql

# Clean old backups (keep last 7 days)
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete
```

### 2. Configuration Backup

```bash
# Backup configuration files
tar -czf config_backup_$(date +%Y%m%d).tar.gz \
  .env \
  migrations/ \
  ssl/ \
  nginx.conf
```

### 3. Recovery Procedures

```bash
# Database recovery
psql -h localhost -U auth_user -d auth_service < backup_20240115_143022.sql

# Service restart
docker-compose restart auth-service

# Verify recovery
curl -f http://localhost:8080/health
```

## Troubleshooting

### 1. Common Issues

#### Database Connection Issues
```bash
# Check database connectivity
psql -h localhost -U auth_user -d auth_service -c "SELECT 1;"

# Check database logs
docker logs postgres

# Verify environment variables
echo $DATABASE_URL
```

#### JWT Token Issues
```bash
# Verify JWT secret
echo $JWT_SECRET_KEY

# Test token validation
curl -X POST http://localhost:8080/v1/iam/validate-token \
  -H "Content-Type: application/json" \
  -d '{"token": "your-token-here"}'
```

#### Performance Issues
```bash
# Check resource usage
docker stats

# Monitor logs
docker logs -f auth-service

# Check database performance
psql -h localhost -U auth_user -d auth_service -c "SELECT * FROM pg_stat_activity;"
```

### 2. Log Analysis

```bash
# Search for errors
grep -i error /var/log/auth-service.log

# Monitor real-time logs
tail -f /var/log/auth-service.log | grep -E "(ERROR|WARN)"

# Analyze request patterns
grep "POST /v1/iam/login" /var/log/auth-service.log | wc -l
```

### 3. Health Checks

```bash
# Service health
curl -f http://localhost:8080/health

# Database health
psql -h localhost -U auth_user -d auth_service -c "SELECT version();"

# Memory usage
free -h

# Disk usage
df -h
```

## Performance Tuning

### 1. Database Optimization

```sql
-- Create indexes for better performance
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX CONCURRENTLY idx_role_permissions_role_id ON role_permissions(role_id);

-- Analyze table statistics
ANALYZE users;
ANALYZE roles;
ANALYZE permissions;
```

### 2. Application Tuning

```rust
// Connection pool configuration
let pool = PgPoolOptions::new()
    .max_connections(20)
    .min_connections(5)
    .connect_timeout(Duration::from_secs(10))
    .idle_timeout(Duration::from_secs(300))
    .max_lifetime(Duration::from_secs(3600))
    .connect(&database_url)
    .await?;
```

### 3. System Tuning

```bash
# Increase file descriptor limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize kernel parameters
echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf
sysctl -p
``` 