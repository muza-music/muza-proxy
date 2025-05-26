"""
Configuration management for Muza-Proxy
"""

import yaml
import logging
import sys


class ProxyConfig:
    """Configuration manager for proxy settings"""

    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        self.config = {}
        self.jwt_public_key = None
        self.logger = logging.getLogger(__name__)
        self.load_config()

    def load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, "r") as config_file:
                self.config = yaml.safe_load(config_file)
                logging.info(f"Configuration loaded from {self.config_path}")
        except FileNotFoundError:
            logging.error(f"Configuration file '{self.config_path}' not found")
            sys.exit(1)
        except yaml.YAMLError as e:
            logging.error(f"Error parsing configuration file: {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
            sys.exit(1)

    def reload_config(self):
        """Reload configuration from file"""
        logging.info("Reloading configuration...")
        self.load_config()

    def set_jwt_public_key(self, public_key):
        """Set JWT public key for token verification"""
        self.jwt_public_key = public_key

    def get_default_server(self):
        """Get default backend server"""
        return self.config.get("default_server", "http://localhost:8080")

    def get_proxy_paths(self):
        """Get configured proxy paths"""
        return self.config.get("proxy_paths", [])

    def get_timeout(self):
        """Get default timeout"""
        return self.config.get("timeout", 30)

    def get_max_retries(self):
        """Get maximum retry attempts"""
        return self.config.get("max_retries", 3)

    def get_log_level(self):
        """Get logging level"""
        return self.config.get("log_level", "INFO")

    def validate_config(self):
        """Validate configuration"""
        errors = []

        # Check required fields
        if not self.config.get("default_server"):
            errors.append("default_server is required in configuration")

        # Validate proxy paths
        proxy_paths = self.get_proxy_paths()
        for i, path_config in enumerate(proxy_paths):
            if "path" not in path_config:
                errors.append(f"proxy_paths[{i}] missing required 'path' field")
            if "server" not in path_config:
                errors.append(f"proxy_paths[{i}] missing required 'server' field")

            # Validate valid_audiences if present
            if "valid_audiences" in path_config:
                audiences = path_config["valid_audiences"]
                if not isinstance(audiences, list):
                    errors.append(f"proxy_paths[{i}].valid_audiences must be a list")
                elif not all(isinstance(aud, str) for aud in audiences):
                    errors.append(f"proxy_paths[{i}].valid_audiences must contain only strings")

        if errors:
            raise ValueError("Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors))

    def get_path_config(self, request_path):
        """Find the best matching proxy path configuration"""
        proxy_paths = self.get_proxy_paths()
        best_match = None
        best_match_length = 0

        for path_config in proxy_paths:
            config_path = path_config["path"]

            # Check if request path starts with config path
            if request_path.startswith(config_path):
                # Prefer longer matches (more specific)
                if len(config_path) > best_match_length:
                    best_match = path_config
                    best_match_length = len(config_path)

        return best_match
