#!/bin/bash
"""
TLS Certificate Generation Script for Muza-Proxy Development

This script generates self-signed TLS certificates for development purposes.
"""

set -e

# Default values
CERT_DIR="certs"
DOMAIN="localhost"
DAYS=365
KEY_SIZE=2048

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Generate self-signed TLS certificates for development"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN     Domain name for certificate (default: localhost)"
    echo "  -o, --output DIR        Output directory for certificates (default: certs)"
    echo "  -t, --days DAYS         Certificate validity in days (default: 365)"
    echo "  -k, --key-size SIZE     RSA key size in bits (default: 2048)"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Generate for localhost"
    echo "  $0 -d example.com -o ./certificates   # Custom domain and output dir"
    echo "  $0 -d *.dev.local -t 30               # Wildcard cert valid for 30 days"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -o|--output)
            CERT_DIR="$2"
            shift 2
            ;;
        -t|--days)
            DAYS="$2"
            shift 2
            ;;
        -k|--key-size)
            KEY_SIZE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

echo -e "${GREEN}=== TLS Certificate Generator for Muza-Proxy ===${NC}"
echo ""
echo "Configuration:"
echo "  Domain: $DOMAIN"
echo "  Output directory: $CERT_DIR"
echo "  Validity: $DAYS days"
echo "  Key size: $KEY_SIZE bits"
echo ""

# Create output directory
mkdir -p "$CERT_DIR"

# Certificate files
PRIVATE_KEY="$CERT_DIR/server.key"
CERTIFICATE="$CERT_DIR/server.crt"
CSR_FILE="$CERT_DIR/server.csr"

# Check if files already exist
if [[ -f "$PRIVATE_KEY" || -f "$CERTIFICATE" ]]; then
    echo -e "${YELLOW}Warning: Certificate files already exist in $CERT_DIR${NC}"
    read -p "Do you want to overwrite them? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo -e "${GREEN}Step 1: Generating private key...${NC}"
openssl genrsa -out "$PRIVATE_KEY" "$KEY_SIZE"

echo -e "${GREEN}Step 2: Creating certificate signing request...${NC}"
openssl req -new -key "$PRIVATE_KEY" -out "$CSR_FILE" -subj "/C=US/ST=Development/L=Local/O=Muza-Proxy/OU=Development/CN=$DOMAIN"

echo -e "${GREEN}Step 3: Generating self-signed certificate...${NC}"
openssl x509 -req -days "$DAYS" -in "$CSR_FILE" -signkey "$PRIVATE_KEY" -out "$CERTIFICATE"

echo -e "${GREEN}Step 4: Setting secure file permissions...${NC}"
chmod 600 "$PRIVATE_KEY"
chmod 644 "$CERTIFICATE"

# Clean up CSR file
rm "$CSR_FILE"

echo -e "${GREEN}Step 5: Verifying certificate...${NC}"
openssl x509 -in "$CERTIFICATE" -text -noout | grep -E "(Subject:|Not Before|Not After|CN=)"

echo ""
echo -e "${GREEN}✓ TLS certificates generated successfully!${NC}"
echo ""
echo "Files created:"
echo "  Private key: $PRIVATE_KEY"
echo "  Certificate: $CERTIFICATE"
echo ""
echo "Usage with muza-proxy:"
echo "  python muza-proxy.py --tls-cert $CERTIFICATE --tls-key $PRIVATE_KEY"
echo ""
echo -e "${YELLOW}Note: These are self-signed certificates for development only.${NC}"
echo -e "${YELLOW}For production, use certificates from a trusted CA.${NC}"
