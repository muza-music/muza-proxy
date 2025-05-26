# Configuration Guide

## Basic Configuration

Create `config.yaml`:

```yaml
default_server: "http://localhost:8080"

proxy_paths:
  - path: "/api/public"
    server: "http://api-server:3000"
    require_bearer: false
  
  - path: "/api/protected"
    server: "http://secure-api:3001"
    require_bearer: true
    valid_audiences: ["user", "admin"]
```

## Configuration Options

### Global Settings

- `default_server`: Default backend for unmatched paths
- `timeout`: Request timeout in seconds (default: 30)
- `max_retries`: Retry attempts (default: 3)
- `log_level`: DEBUG, INFO, WARNING, ERROR

### Proxy Paths

- `path`: URL path to match
- `server`: Backend server URL
- `require_bearer`: Enable JWT validation (default: false)
- `valid_audiences`: Required token audiences (optional)
- `timeout`: Path-specific timeout
- `headers`: Additional headers to add

## Examples

### Role-Based Access

```yaml
proxy_paths:
  # Public access
  - path: "/api/public"
    server: "http://public-api:3000"
    require_bearer: false
  
  # User access
  - path: "/api/user"
    server: "http://user-api:3001"
    require_bearer: true
    valid_audiences: ["user", "admin"]
  
  # Admin only
  - path: "/api/admin"
    server: "http://admin-api:4000"
    require_bearer: true
    valid_audiences: ["admin"]
```

### Microservices

```yaml
proxy_paths:
  - path: "/api/users"
    server: "http://user-service:3000"
    require_bearer: true
    headers:
      X-Service: "user-service"
  
  - path: "/api/orders"
    server: "http://order-service:3001"
    require_bearer: true
    valid_audiences: ["customer", "staff"]
    timeout: 45
```

## Command Line

```bash
python muza-proxy.py \
  --config config.yaml \
  --host 0.0.0.0 \
  --port 8443 \
  --tls-cert server.crt \
  --tls-key server.key \
  --jwt-public-key public_key.pem \
  --log-level INFO
```

## Validation

```bash
# Validate configuration
make validate

# Start development server
make start-dev
```
