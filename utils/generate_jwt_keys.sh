#!/bin/bash
"""
JWT Key Generation Script for Muza-Proxy

This script generates RSA key pairs for JWT token signing and verification.
"""

set -e

# Default values
KEY_DIR="keys"
KEY_SIZE=2048
PROTECTED=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Generate RSA key pairs for JWT token signing and verification"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR        Output directory for keys (default: keys)"
    echo "  -k, --key-size SIZE     RSA key size in bits (default: 2048)"
    echo "  -p, --protected         Generate password-protected private key"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       # Generate basic key pair"
    echo "  $0 -o ./jwt-keys -k 4096 # Custom directory and 4096-bit keys"
    echo "  $0 -p                    # Password-protected private key"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            KEY_DIR="$2"
            shift 2
            ;;
        -k|--key-size)
            KEY_SIZE="$2"
            shift 2
            ;;
        -p|--protected)
            PROTECTED=true
            shift
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

echo -e "${GREEN}=== JWT Key Generator for Muza-Proxy ===${NC}"
echo ""
echo "Configuration:"
echo "  Output directory: $KEY_DIR"
echo "  Key size: $KEY_SIZE bits"
echo "  Password protected: $PROTECTED"
echo ""

# Create output directory
mkdir -p "$KEY_DIR"

# Key files
PRIVATE_KEY="$KEY_DIR/private_key.pem"
PUBLIC_KEY="$KEY_DIR/public_key.pem"

# Check if files already exist
if [[ -f "$PRIVATE_KEY" || -f "$PUBLIC_KEY" ]]; then
    echo -e "${YELLOW}Warning: Key files already exist in $KEY_DIR${NC}"
    read -p "Do you want to overwrite them? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo -e "${GREEN}Step 1: Generating private key...${NC}"
if [[ "$PROTECTED" == true ]]; then
    echo "You will be prompted to enter a passphrase for the private key."
    openssl genrsa -aes256 -out "$PRIVATE_KEY" "$KEY_SIZE"
else
    openssl genrsa -out "$PRIVATE_KEY" "$KEY_SIZE"
fi

echo -e "${GREEN}Step 2: Extracting public key...${NC}"
if [[ "$PROTECTED" == true ]]; then
    echo "Enter the private key passphrase to extract the public key:"
fi
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

echo -e "${GREEN}Step 3: Setting secure file permissions...${NC}"
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo -e "${GREEN}Step 4: Verifying keys...${NC}"
# Test that the keys work together
TEST_DATA="test-message-for-jwt-verification"
SIGNATURE_FILE=$(mktemp)

# Sign test data with private key
if [[ "$PROTECTED" == true ]]; then
    echo "Enter the private key passphrase for verification:"
fi
echo -n "$TEST_DATA" | openssl dgst -sha256 -sign "$PRIVATE_KEY" > "$SIGNATURE_FILE"

# Verify signature with public key
if echo -n "$TEST_DATA" | openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE_FILE" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Key pair verification successful${NC}"
else
    echo -e "${RED}✗ Key pair verification failed${NC}"
    rm "$SIGNATURE_FILE"
    exit 1
fi

# Clean up
rm "$SIGNATURE_FILE"

echo ""
echo -e "${GREEN}✓ JWT key pair generated successfully!${NC}"
echo ""
echo "Files created:"
echo "  Private key: $PRIVATE_KEY"
echo "  Public key:  $PUBLIC_KEY"
echo ""
echo "Usage with muza-proxy:"
echo "  python muza-proxy.py --jwt-private-key $PRIVATE_KEY --jwt-public-key $PUBLIC_KEY"
echo ""
echo "Generate tokens with:"
echo "  python utils/sign.py $PRIVATE_KEY user_id"
echo ""
echo "Verify tokens with:"
echo "  python utils/verify.py \"token\" $PUBLIC_KEY"
echo ""
if [[ "$PROTECTED" == true ]]; then
    echo -e "${YELLOW}Note: Remember your passphrase - it will be needed to use the private key.${NC}"
fi
echo -e "${YELLOW}Keep the private key secure and never share it!${NC}"
