"""
HTTP/HTTPS proxy server implementation
"""

import logging
import ssl
from http.server import HTTPServer

from .handler import ProxyHandler


def setup_logging(log_level="INFO"):
    """Setup logging configuration"""
    level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


class ProxyServer:
    """Main proxy server class"""

    def __init__(self, config, jwt_validator):
        self.config = config
        self.jwt_validator = jwt_validator
        self.server = None
        self.logger = logging.getLogger(__name__)

    def create_server(self, host, port):
        """Create HTTP server"""

        def handler_factory(*args, **kwargs):
            # Create a handler instance that has access to config and jwt_validator
            handler = ProxyHandler(*args, **kwargs)
            # Pass server instance to handler so it can access config and jwt_validator
            handler.server.config = self.config
            handler.server.jwt_validator = self.jwt_validator
            return handler

        self.server = HTTPServer((host, port), handler_factory)
        # Store config and jwt_validator on server instance for handler access
        self.server.config = self.config
        self.server.jwt_validator = self.jwt_validator
        self.logger.info(f"Server created on {host}:{port}")

    def setup_tls(self, cert_file, key_file):
        """Setup TLS/SSL for HTTPS"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.logger.info("TLS enabled")

    def start(self):
        """Start the server"""
        try:
            self.logger.info("Starting proxy server...")
            self.server.serve_forever()
        except KeyboardInterrupt:
            self.logger.info("Server shutdown requested")
            self.stop()

    def stop(self):
        """Stop the server"""
        if self.server:
            self.server.shutdown()
            self.logger.info("Server stopped")
