"""
Muza-Proxy - HTTP/HTTPS Proxy Server

A configurable proxy server with path-based routing and JWT authentication.
"""

__version__ = "1.0.0"
__author__ = "Muza-Proxy Team"
__email__ = "contact@muza-proxy.com"

from .config import ProxyConfig
from .auth import JWTValidator
from .server import ProxyServer
from .handler import ProxyHandler

__all__ = ["ProxyConfig", "JWTValidator", "ProxyServer", "ProxyHandler"]
