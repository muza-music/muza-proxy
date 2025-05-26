#!/usr/bin/env python3
"""
Muza-Proxy - HTTP/HTTPS Proxy Server

Main entry point for the proxy server.
"""

import argparse
import logging
import sys
from pathlib import Path

from src.config import ProxyConfig
from src.auth import JWTValidator, load_jwt_keys
from src.server import ProxyServer, setup_logging


# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Muza-Proxy - HTTP/HTTPS proxy server with authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --config config.yaml --tls-cert server.crt --tls-key server.key
  %(prog)s --config config.yaml --jwt-public-key public.pem --port 8443
  %(prog)s --no-tls --port 8080  # HTTP only for development
        """,
    )

    parser.add_argument(
        "--config",
        "-c",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )

    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")

    parser.add_argument("--port", "-p", type=int, default=8443, help="Port to listen on (default: 8443)")

    parser.add_argument("--tls-cert", help="Path to TLS certificate file")

    parser.add_argument("--tls-key", help="Path to TLS private key file")

    parser.add_argument("--jwt-public-key", help="Path to JWT public key file")

    parser.add_argument("--jwt-private-key", help="Path to JWT private key file (optional)")

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    parser.add_argument("--no-tls", action="store_true", help="Disable TLS and run HTTP only (development mode)")

    parser.add_argument("--validate-only", action="store_true", help="Validate configuration and exit")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Load configuration
    try:
        config = ProxyConfig(args.config)
        config.validate_config()
        logger.info("✓ Configuration validation successful")
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        sys.exit(1)

    if args.validate_only:
        logger.info("Configuration is valid")
        sys.exit(0)

    # Load JWT keys if provided
    jwt_validator = None
    if args.jwt_public_key:
        try:
            public_key, private_key = load_jwt_keys(args.jwt_public_key, args.jwt_private_key)
            config.set_jwt_public_key(public_key)
            jwt_validator = JWTValidator(public_key)
            logger.info("JWT authentication enabled")
        except Exception as e:
            logger.error(f"Failed to load JWT keys: {e}")
            sys.exit(1)
    else:
        logger.warning("No JWT public key provided - authentication will be disabled")
        jwt_validator = JWTValidator(None)  # Dummy validator

    # Create and configure server
    try:
        proxy_server = ProxyServer(config, jwt_validator)
        proxy_server.create_server(args.host, args.port)

        # Setup TLS if enabled
        protocol = "http"
        if not args.no_tls:
            if not args.tls_cert or not args.tls_key:
                logger.error("TLS certificate and key are required (use --no-tls for HTTP only)")
                sys.exit(1)

            proxy_server.setup_tls(args.tls_cert, args.tls_key)
            protocol = "https"
        else:
            logger.warning("Running in HTTP mode - not suitable for production")

        # Start server
        logger.info(f"Starting muza-proxy on {protocol}://{args.host}:{args.port}")
        logger.info(f"Configuration: {args.config}")

        proxy_server.start()

    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
