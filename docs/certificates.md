# Certificate Management

## Quick Setup

```bash
# Generate TLS certificates and JWT keys
make certs-and-keys

# Or individually
make certs    # TLS certificates only
make keys     # JWT keys only
```

## Manual Generation

### TLS Certificates (Development)

```bash
# Generate self-signed certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=Dev/L=Local/O=MuzaProxy/CN=localhost"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
rm server.csr
```

### JWT Keys

```bash
# Generate RSA key pair
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

## File Permissions

```bash
# Set proper permissions
chmod 600 certs/server.key keys/private_key.pem
chmod 644 certs/server.crt keys/public_key.pem
```

## Production Setup

### Let's Encrypt

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d your-domain.com
```

### Production Structure

```txt
/etc/muza-proxy/
├── certs/
│   ├── server.crt
│   └── server.key
├── keys/
│   ├── private_key.pem
│   └── public_key.pem
└── config.yaml
```

## Validation

```bash
# Verify certificate matches key
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
# Hashes should match

# Test JWT key pair
echo "test" | openssl rsautl -sign -inkey private_key.pem | \
openssl rsautl -verify -pubin -inkey public_key.pem
```

## Certificate Monitoring

```bash
# Check expiration
openssl x509 -enddate -noout -in server.crt

# Days until expiration
openssl x509 -enddate -noout -in server.crt | cut -d= -f2 | \
xargs -I {} date -d {} +%s | \
xargs -I {} expr \( {} - $(date +%s) \) / 86400
```

## Docker Deployment

```yaml
# docker-compose.yml
services:
  muza-proxy:
    build: .
    ports:
      - "8443:8443"
    volumes:
      - ./certs:/app/certs:ro
      - ./keys:/app/keys:ro
      - ./config.yaml:/app/config.yaml:ro
```

## Security Best Practices

1. **Separate environments**: Different keys for dev/staging/production
2. **Regular rotation**: Rotate keys quarterly
3. **Secure storage**: Proper file permissions and ownership
4. **Monitoring**: Alert on certificate expiration
5. **Backup**: Secure key backups
