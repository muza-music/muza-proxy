# Authentication Guide

## Overview

Muza-proxy uses JWT tokens with RSA keys for authentication. Protected endpoints require a Bearer token with valid audience claims.

## Token Format

```json
{
  "iss": "muza-proxy",
  "sub": "user-id", 
  "aud": "user",
  "iat": 1640995200,
  "exp": 1640998800
}
```

## Generating Tokens

### Using Makefile

```bash
# Basic token
make generate-token USER=john_doe

# With specific audience
make generate-token USER=admin_user AUD=admin

# Custom expiration (hours)
make generate-token USER=temp_user AUD=user EXPIRES=1
```

### Using Utility Directly

```bash
# Basic token (24h expiration)
python utils/sign.py keys/private_key.pem john_doe

# Custom audience and expiration
python utils/sign.py keys/private_key.pem admin_user \
  --audience "admin" --expires 168
```

## Verifying Tokens

```bash
# Verify token
make verify-token TOKEN="eyJhbGci..."

# Or directly
python utils/verify.py "token" keys/public_key.pem
```

## Using Tokens

### With curl

```bash
curl -H "Authorization: Bearer <token>" \
     https://localhost:8443/api/protected
```

### With Python

```python
import requests

headers = {'Authorization': f'Bearer {token}'}
response = requests.get('https://localhost:8443/api/protected', headers=headers)
```

## Audience-Based Access

Configure different access levels:

```yaml
proxy_paths:
  # Any authenticated user
  - path: "/api/profile"
    server: "http://profile-service:3000"
    require_bearer: true
  
  # Specific audiences
  - path: "/api/admin"
    server: "http://admin-service:4000"
    require_bearer: true
    valid_audiences: ["admin"]
  
  # Multiple audiences
  - path: "/api/support"
    server: "http://support-service:3001"
    require_bearer: true
    valid_audiences: ["support", "admin"]
```

## Security Best Practices

1. **Short expiration**: Use 1-24 hour tokens
2. **HTTPS only**: Always use TLS for token transmission
3. **Secure storage**: Store tokens securely on client
4. **Regular key rotation**: Rotate JWT keys periodically
5. **Audience validation**: Use specific audiences for role-based access

## Troubleshooting

```bash
# Check token without verification (debug)
python -c "
import jwt
payload = jwt.decode('$TOKEN', options={'verify_signature': False})
print(payload)
"

# Validate setup
make validate
make start-dev
```
