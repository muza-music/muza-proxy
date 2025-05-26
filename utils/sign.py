#!/usr/bin/env python3
"""
JWT Token Signing Utility for Muza-Proxy

This utility creates and signs JWT tokens for authentication with the muza-proxy server.
"""

import jwt
import time
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path


def load_private_key(private_key_path):
    """Load private key from file"""
    try:
        with open(private_key_path, "r") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print(f"Error: Private key file '{private_key_path}' does not exist.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading private key: {e}", file=sys.stderr)
        sys.exit(1)


def sign_token(private_key, user_id, expires_in_hours=24, issuer="muza-proxy", audience="proxy-client"):
    """
    Sign a new JWT token

    Args:
        private_key (str): RSA private key in PEM format
        user_id (str): User identifier for the token subject
        expires_in_hours (int): Token expiration time in hours
        issuer (str): Token issuer
        audience (str|list): Token audience(s) - can be string or list

    Returns:
        str: Signed JWT token
    """
    current_time = int(time.time())
    expiration_time = current_time + (expires_in_hours * 3600)

    # Handle multiple audiences
    if isinstance(audience, str) and "," in audience:
        # Convert comma-separated string to list
        audience = [aud.strip() for aud in audience.split(",")]

    # Token payload
    payload = {
        "iss": issuer,
        "sub": user_id,
        "aud": audience,
        "iat": current_time,
        "exp": expiration_time,
        "nbf": current_time,  # Not before (token not valid before this time)
    }

    try:
        # Sign token with RS256 algorithm
        token = jwt.encode(payload, private_key, algorithm="RS256")
        return token
    except Exception as e:
        print(f"Error signing token: {e}", file=sys.stderr)
        sys.exit(1)


def format_expiration_time(expires_in_hours):
    """Format expiration time for display"""
    expiration_datetime = datetime.now() + timedelta(hours=expires_in_hours)
    return expiration_datetime.strftime("%Y-%m-%d %H:%M:%S UTC")


def main():
    parser = argparse.ArgumentParser(
        description="Sign JWT tokens for muza-proxy authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s private_key.pem john_doe
  %(prog)s private_key.pem admin_user --expires 168
  %(prog)s keys/private.pem user123 --expires 1 --issuer "custom-proxy"
        """,
    )

    parser.add_argument("private_key_path", help="Path to the RSA private key file (PEM format)")

    parser.add_argument("user_id", help="User identifier for the token subject")

    parser.add_argument("--expires", "-e", type=int, default=24, help="Token expiration time in hours (default: 24)")

    parser.add_argument("--issuer", "-i", default="muza-proxy", help="Token issuer (default: muza-proxy)")

    parser.add_argument("--audience", "-a", default="proxy-client", help="Token audience (default: proxy-client)")

    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed token information")

    args = parser.parse_args()

    # Validate private key file exists
    if not Path(args.private_key_path).exists():
        print(f"Error: Private key file '{args.private_key_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Load private key
    private_key = load_private_key(args.private_key_path)

    # Sign token
    token = sign_token(private_key, args.user_id, args.expires, args.issuer, args.audience)

    # Display results
    if args.verbose:
        print("=" * 60)
        print("JWT Token Generated Successfully")
        print("=" * 60)
        print(f"User ID: {args.user_id}")
        print(f"Issuer: {args.issuer}")
        print(f"Audience: {args.audience}")
        print(f"Expires in: {args.expires} hours")
        print(f"Expires at: {format_expiration_time(args.expires)}")
        print(f"Private key: {args.private_key_path}")
        print("-" * 60)
        print("Bearer Token:")
    else:
        print(f"Bearer token for user '{args.user_id}' (expires in {args.expires} hours):")

    print(token)

    if args.verbose:
        print("-" * 60)
        print("Usage example:")
        print(f'curl -H "Authorization: Bearer {token}" \\')
        print("     https://your-proxy-server:8443/api/protected/data")


if __name__ == "__main__":
    main()
