"""
HTTP request handler for Muza-Proxy
"""

import json
import logging
import time
import httpx
import socket
import ssl
from http.server import BaseHTTPRequestHandler
from urllib.parse import urljoin

from .auth import AuthenticationManager


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the proxy server"""

    def __init__(self, request, client_address, server):
        self.config = server.config
        self.auth_manager = AuthenticationManager(server.jwt_validator)
        self.logger = logging.getLogger(__name__)
        self._response_started = False
        self._headers_sent = False
        self._connection_broken = False

        # Create httpx client with connection pooling and timeouts
        try:
            self.http_client = httpx.Client(
                timeout=httpx.Timeout(30.0),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
                http2=True,  # Enable HTTP/2 support
                verify=True,
            )
        except Exception as e:
            self.logger.error(f"Failed to create HTTP client: {e}")
            self.http_client = None

        super().__init__(request, client_address, server)

    def log_message(self, format, *args):
        """Override to use proper logging"""
        self.logger.info(f"{self.client_address[0]} - {format % args}")

    def _check_connection(self):
        """Check if the connection is still valid"""
        if self._connection_broken:
            return False
        
        return True

    def _safe_send_response(self, status_code):
        """Safely send response status"""
        if self._response_started or self._connection_broken:
            return False
        
        try:
            self.send_response(status_code)
            self._response_started = True
            return True
        except (socket.error, ssl.SSLError, BrokenPipeError, ConnectionResetError) as e:
            self.logger.debug(f"Failed to send response status: {e}")
            self._connection_broken = True
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending response status: {e}")
            self._connection_broken = True
            return False

    def _safe_send_header(self, name, value):
        """Safely send a header"""
        if self._headers_sent or self._connection_broken:
            return False
        
        try:
            self.send_header(name, value)
            return True
        except (socket.error, ssl.SSLError, BrokenPipeError, ConnectionResetError) as e:
            self.logger.debug(f"Failed to send header {name}: {e}")
            self._connection_broken = True
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending header {name}: {e}")
            self._connection_broken = True
            return False

    def _safe_end_headers(self):
        """Safely end headers"""
        if self._headers_sent or self._connection_broken:
            return False
        
        try:
            self.end_headers()
            self._headers_sent = True
            return True
        except (socket.error, ssl.SSLError, BrokenPipeError, ConnectionResetError) as e:
            self.logger.debug(f"Failed to end headers: {e}")
            self._connection_broken = True
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error ending headers: {e}")
            self._connection_broken = True
            return False

    def _safe_write_data(self, data):
        """Safely write data to response"""
        if self._connection_broken:
            return False
        
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            self.wfile.write(data)
            self.wfile.flush()
            return True
        except (socket.error, ssl.SSLError, BrokenPipeError, ConnectionResetError) as e:
            self.logger.debug(f"Failed to write response data: {e}")
            self._connection_broken = True
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error writing response data: {e}")
            self._connection_broken = True
            return False

    def do_GET(self):
        """Handle GET requests"""
        self.handle_request()

    def do_POST(self):
        """Handle POST requests"""
        self.handle_request()

    def do_PUT(self):
        """Handle PUT requests"""
        self.handle_request()

    def do_DELETE(self):
        """Handle DELETE requests"""
        self.handle_request()

    def do_PATCH(self):
        """Handle PATCH requests"""
        self.handle_request()

    def do_HEAD(self):
        """Handle HEAD requests"""
        self.handle_request()

    def do_OPTIONS(self):
        """Handle OPTIONS requests"""
        self.handle_request()

    def handle_request(self):
        """Main request handling logic"""
        start_time = time.time()
        client_ip = self.client_address[0]

        try:
            self.logger.debug(f"Handling {self.command} {self.path} from {client_ip}")

            # Check if HTTP client is available
            if not self.http_client:
                self.send_error_response(500, "Service Unavailable")
                return

            # Handle special endpoints
            if self.path == "/health":
                self.handle_health_check()
                return
            elif self.path == "/ready":
                self.handle_readiness_check()
                return

            # Find matching proxy path
            path_config = self.config.get_path_config(self.path)
            if not path_config:
                self.proxy_to_default()
                return

            # Check authentication if required
            auth_result = self.auth_manager.authenticate_request(self.headers, path_config)
            if not auth_result["valid"]:
                self.send_authentication_error(auth_result["error"])
                return

            # Proxy the request
            self.proxy_request(path_config, auth_result.get("payload"))

        except (socket.error, ssl.SSLError, BrokenPipeError, ConnectionResetError) as e:
            self.logger.warning(f"Connection error handling request from {client_ip}: {e}")
            self._connection_broken = True
            # Don't try to send error response for connection errors
        except Exception as e:
            self.logger.error(f"Error handling request from {client_ip}: {e}")
            # Only try to send error response if connection is still valid
            if not self._connection_broken:
                try:
                    self.send_error_response(500, "Internal Server Error")
                except Exception as err:
                    self.logger.error(f"Failed to send error response: {err}")
                    self._connection_broken = True
        finally:
            duration = time.time() - start_time
            if not self._connection_broken:
                self.logger.info(f"Request completed in {duration:.3f}s")
            else:
                self.logger.debug(f"Request terminated due to connection error after {duration:.3f}s")

    def handle_health_check(self):
        """Handle health check endpoint"""
        response = {"status": "healthy", "timestamp": time.time(), "version": "1.0.0"}
        self.send_json_response(200, response)

    def handle_readiness_check(self):
        """Handle readiness check endpoint"""
        if not self.http_client:
            response = {
                "status": "not ready",
                "timestamp": time.time(),
                "error": "HTTP client not available"
            }
            self.send_json_response(503, response)
            return

        # Check if backend services are reachable
        ready = True
        checks = []

        for path_config in self.config.get_proxy_paths():
            server_url = path_config["server"]
            try:
                response = self.http_client.get(f"{server_url}/health", timeout=5.0)
                checks.append(
                    {
                        "service": server_url,
                        "status": "ready" if response.status_code < 500 else "unhealthy",
                    }
                )
            except Exception:
                checks.append({"service": server_url, "status": "unreachable"})
                ready = False

        response = {
            "status": "ready" if ready else "not ready",
            "timestamp": time.time(),
            "checks": checks,
        }

        status_code = 200 if ready else 503
        self.send_json_response(status_code, response)

    def proxy_request(self, path_config, auth_payload=None):
        """Proxy request to backend server using httpx"""
        if not self.http_client:
            self.send_error_response(503, "Service Unavailable")
            return

        backend_server = path_config["server"]
        timeout = path_config.get("timeout", self.config.get_timeout())
        additional_headers = path_config.get("headers", {})
        config_path = path_config["path"]

        # Build target URL by removing the configured path prefix
        remaining_path = self.path
        if self.path.startswith(config_path):
            # Remove the configured path prefix
            prefix_length = len(config_path)
            remaining_path = self.path[prefix_length:]
            # Ensure remaining path starts with / if it's not empty
            if remaining_path and not remaining_path.startswith("/"):
                remaining_path = "/" + remaining_path
            elif not remaining_path:
                remaining_path = "/"

        target_url = urljoin(backend_server.rstrip("/") + "/", remaining_path.lstrip("/"))

        # Prepare headers
        headers = {}
        for header, value in self.headers.items():
            # Skip hop-by-hop headers
            if header.lower() not in [
                "connection",
                "upgrade",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailers",
                "transfer-encoding",
            ]:
                headers[header] = value

        # Add additional headers from configuration
        headers.update(additional_headers)

        # Add proxy identification headers
        headers["X-Forwarded-For"] = self.client_address[0]
        headers["X-Forwarded-Proto"] = "https" if hasattr(self.request, "context") else "http"
        headers["X-Forwarded-Host"] = self.headers.get("Host", "unknown")

        # Add user information from JWT payload if available
        if auth_payload:
            headers["X-User-ID"] = auth_payload.get("sub", "unknown")
            if "aud" in auth_payload:
                audiences = auth_payload["aud"]
                if isinstance(audiences, list):
                    headers["X-User-Roles"] = ",".join(audiences)
                else:
                    headers["X-User-Roles"] = audiences

        # Get request body for POST/PUT/PATCH
        body = None
        if self.command in ["POST", "PUT", "PATCH"]:
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length > 0:
                    body = self.rfile.read(content_length)
            except (ValueError, socket.error, ssl.SSLError) as e:
                self.logger.warning(f"Error reading request body: {e}")
                self.send_error_response(400, "Bad Request")
                return

        # Make request to backend using httpx
        try:
            self.logger.debug(f"Proxying to {target_url} (original path: {self.path}, config path: {config_path})")

            # Use httpx for the request with streaming
            with self.http_client.stream(
                method=self.command,
                url=target_url,
                headers=headers,
                content=body,
                timeout=timeout,
                follow_redirects=False,
            ) as response:

                # Send response back to client
                if not self._safe_send_response(response.status_code):
                    return

                # Forward response headers
                for header, value in response.headers.items():
                    if header.lower() not in ["connection", "transfer-encoding"]:
                        if not self._safe_send_header(header, value):
                            return

                if not self._safe_end_headers():
                    return

                # Stream response body efficiently
                for chunk in response.iter_bytes(chunk_size=8192):
                    if chunk:
                        if not self._safe_write_data(chunk):
                            return

            self.logger.info(f"Proxied {self.command} {self.path} -> {target_url} [{response.status_code}]")

        except httpx.TimeoutException:
            self.logger.warning(f"Timeout proxying to {target_url}")
            self.send_error_response(504, "Gateway Timeout")
        except httpx.ConnectError:
            self.logger.warning(f"Connection error proxying to {target_url}")
            self.send_error_response(502, "Bad Gateway")
        except httpx.HTTPStatusError as e:
            self.logger.warning(f"HTTP error proxying to {target_url}: {e}")
            self.send_error_response(e.response.status_code, str(e))
        except (socket.error, ssl.SSLError, BrokenPipeError, ConnectionResetError) as e:
            self.logger.warning(f"Connection error during proxy to {target_url}: {e}")
            self._connection_broken = True
        except Exception as e:
            self.logger.error(f"Error proxying request to {target_url}: {e}")
            self.send_error_response(500, "Internal Server Error")

    def proxy_to_default(self):
        """Proxy request to default server"""
        default_config = {
            "server": self.config.get_default_server(),
            "timeout": self.config.get_timeout(),
        }
        self.logger.debug(f"No specific path match, proxying to default: {default_config['server']}")
        self.proxy_request(default_config)

    def send_authentication_error(self, error_message):
        """Send authentication error response"""
        if self._connection_broken:
            return

        response = {
            "error": "Authentication failed",
            "message": error_message,
            "timestamp": time.time(),
        }

        if not self._safe_send_response(401):
            return

        if not self._safe_send_header("WWW-Authenticate", 'Bearer realm="muza-proxy"'):
            return

        if not self._safe_send_header("Content-Type", "application/json"):
            return

        response_data = json.dumps(response, indent=2)
        if not self._safe_send_header("Content-Length", str(len(response_data))):
            return

        if not self._safe_end_headers():
            return

        self._safe_write_data(response_data)

    def send_error_response(self, status_code, message):
        """Send error response"""
        if self._connection_broken:
            return

        response = {"error": message, "status_code": status_code, "timestamp": time.time()}
        self.send_json_response(status_code, response)

    def send_json_response(self, status_code, data):
        """Send JSON response"""
        if self._connection_broken:
            return

        try:
            response_data = json.dumps(data, indent=2)
        except (TypeError, ValueError) as e:
            self.logger.error(f"Error serializing response data: {e}")
            # Fallback to simple error message
            response_data = json.dumps({"error": "Internal Server Error", "status_code": 500})
            status_code = 500

        if not self._safe_send_response(status_code):
            return

        if not self._safe_send_header("Content-Type", "application/json"):
            return

        if not self._safe_send_header("Content-Length", str(len(response_data))):
            return

        if not self._safe_end_headers():
            return

        self._safe_write_data(response_data)

    def __del__(self):
        """Clean up httpx client"""
        try:
            if hasattr(self, "http_client") and self.http_client:
                self.http_client.close()
        except Exception:
            pass
