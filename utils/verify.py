#!/usr/bin/env python3
"""
JWT Token Verification Utility for Muza-Proxy

This utility verifies JWT tokens against a public key for testing purposes.
"""

import jwt
import json
import argparse
import sys
from datetime import datetime
from pathlib import Path


def load_public_key(public_key_path):
    """Load public key from file"""
    try:
        with open(public_key_path, "r") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print(f"Error: Public key file '{public_key_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading public key: {e}")
        sys.exit(1)


def verify_token(token, public_key, issuer="muza-proxy", audience="proxy-client"):
    """
    Verify a JWT token

    Args:
        token (str): JWT token to verify
        public_key (str): RSA public key in PEM format
        issuer (str): Expected token issuer
        audience (str): Expected token audience (can be None for any audience)

    Returns:
        dict: Token payload if valid, error information if invalid
    """
    try:
        # Build decode options
        decode_options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_iss": True,
            "verify_aud": audience is not None,  # Only verify audience if specified
        }

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=audience if audience else None,
            issuer=issuer,
            options=decode_options,
        )
        return {"status": "valid", "payload": payload}
    except jwt.ExpiredSignatureError:
        return {"status": "error", "error": "Token has expired"}
    except jwt.InvalidAudienceError:
        return {"status": "error", "error": f"Invalid audience (expected: {audience})"}
    except jwt.InvalidIssuerError:
        return {"status": "error", "error": f"Invalid issuer (expected: {issuer})"}
    except jwt.InvalidSignatureError:
        return {"status": "error", "error": "Invalid token signature"}
    except jwt.InvalidTokenError as e:
        return {"status": "error", "error": f"Invalid token: {str(e)}"}
    except Exception as e:
        return {"status": "error", "error": f"Verification failed: {str(e)}"}


def format_timestamp(timestamp):
    """Format Unix timestamp to human-readable string"""
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")


def main():
    parser = argparse.ArgumentParser(
        description="Verify JWT tokens for muza-proxy authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." public_key.pem
  %(prog)s token.txt keys/public.pem --issuer "custom-proxy"
        """,
    )

    parser.add_argument("token", help="JWT token to verify (or path to file containing token)")

    parser.add_argument("public_key_path", help="Path to the RSA public key file (PEM format)")

    parser.add_argument("--issuer", "-i", default="muza-proxy", help="Expected token issuer (default: muza-proxy)")

    parser.add_argument(
        "--audience",
        "-a",
        default="any",
        help='Expected token audience (default: any, use "any" to skip audience validation)',
    )

    parser.add_argument("--json", "-j", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    # Check if token is a file path or the token itself
    # Only check if it looks like a reasonable filename (not too long, no dots indicating JWT structure)
    if (
        len(args.token) < 255 and "." not in args.token and not args.token.startswith("eyJ")
    ):  # JWT tokens start with eyJ
        try:
            if Path(args.token).exists():
                with open(args.token, "r") as token_file:
                    token = token_file.read().strip()
            else:
                token = args.token
        except Exception as e:
            print(f"Error reading token file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        token = args.token

    # Validate public key file exists
    if not Path(args.public_key_path).exists():
        print(f"Error: Public key file '{args.public_key_path}' does not exist.")
        sys.exit(1)

    # Load public key
    public_key = load_public_key(args.public_key_path)

    # Handle "any" audience
    audience = None if args.audience.lower() == "any" else args.audience

    # Verify token
    result = verify_token(token, public_key, args.issuer, audience)

    if args.json:
        # JSON output
        print(json.dumps(result, indent=2))
    else:
        # Human-readable output
        print("=" * 60)
        print("JWT Token Verification Result")
        print("=" * 60)

        if result["status"] == "valid":
            payload = result["payload"]
            print("✓ Token is VALID")
            print()
            print("Token Details:")
            print(f"  Subject (sub): {payload.get('sub', 'N/A')}")
            print(f"  Issuer (iss): {payload.get('iss', 'N/A')}")
            print(f"  Audience (aud): {payload.get('aud', 'N/A')}")

            if "iat" in payload:
                print(f"  Issued at: {format_timestamp(payload['iat'])}")
            if "nbf" in payload:
                print(f"  Not before: {format_timestamp(payload['nbf'])}")
            if "exp" in payload:
                print(f"  Expires at: {format_timestamp(payload['exp'])}")

            # Show custom claims
            standard_claims = {"sub", "iss", "aud", "iat", "exp", "nbf"}
            custom_claims = {k: v for k, v in payload.items() if k not in standard_claims}
            if custom_claims:
                print("  Custom claims:")
                for key, value in custom_claims.items():
                    print(f"    {key}: {value}")

            # Handle audience display
            token_audience = payload.get("aud", "N/A")
            if isinstance(token_audience, list):
                print(f"  Audiences (aud): {', '.join(token_audience)}")
            else:
                print(f"  Audience (aud): {token_audience}")

            # Show audience validation info
            if audience:
                print(f"\n  Audience validation: Expected '{audience}' ✓")
            else:
                print("\n  Audience validation: Skipped (any audience accepted)")
        else:
            print("✗ Token is INVALID")
            print(f"Error: {result['error']}")

    # Exit with appropriate code
    sys.exit(0 if result["status"] == "valid" else 1)


if __name__ == "__main__":
    main()
