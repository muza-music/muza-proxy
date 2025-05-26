# Muza-Proxy

A Python HTTP/HTTPS proxy server with path-based routing and JWT authentication.

## Features

- **Path-based routing**: Route requests to different backends based on URL paths
- **JWT authentication**: Bearer token validation with audience-based access control
- **TLS/SSL support**: HTTPS with custom certificates
- **YAML configuration**: Easy configuration management

## Quick Start

### Setup

```bash
# Complete setup (installs deps, generates certs/keys)
make setup-dev

# Start development server (HTTP on port 8080)
make start
```

### Generate & Test Tokens

```bash
# Generate token
make generate-token USER=testuser AUD=user

# Test protected endpoint
TOKEN="<generated-token>"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/protected
```

## Configuration

Edit `config.yaml`:

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

## Common Commands

```bash
# Development
make start-dev             # Start HTTP server
make start                 # Start HTTPS server
make validate              # Validate configuration

# Tokens
make generate-token USER=john AUD=admin
make verify-token TOKEN="eyJhbGci..."

# Setup
make certs                 # Generate TLS certificates
make keys                  # Generate JWT keys
make clean                 # Clean temp files
```

## Production

```bash
# Install production dependencies
make install

# Start with HTTPS
python muza-proxy.py \
  --config config.yaml \
  --tls-cert certs/server.crt \
  --tls-key certs/server.key \
  --jwt-public-key keys/public_key.pem
```

## Documentation

- **[Configuration](docs/configuration.md)** - Detailed configuration options
- **[Authentication](docs/authentication.md)** - JWT token management
- **[Certificates](docs/certificates.md)** - TLS and JWT key generation

## Requirements

- Python 3.7+
- PyYAML, PyJWT, cryptography, httpx
