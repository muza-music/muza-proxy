"""
JWT authentication and authorization for Muza-Proxy
"""

import jwt
import logging
import time
import sys


class JWTValidator:
    """JWT token validation with audience support"""

    def __init__(self, public_key, issuer="muza-proxy"):
        self.public_key = public_key
        self.issuer = issuer
        self.enabled = public_key is not None
        self.logger = logging.getLogger(__name__)

    def validate_token(self, token, required_audiences=None):
        """
        Validate JWT token with optional audience validation

        Args:
            token (str): JWT token to validate
            required_audiences (list): List of valid audiences, None for any audience

        Returns:
            dict: Validation result with payload or error
        """
        if not self.enabled:
            return {"valid": False, "error": "JWT validation disabled - no public key provided"}

        try:
            # Build decode options
            decode_options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": False,  # We'll handle audience validation manually
            }

            # Decode token without audience verification first
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                options=decode_options,
            )

            # Manual audience validation if required
            if required_audiences is not None:
                token_audiences = payload.get("aud", [])
                if isinstance(token_audiences, str):
                    token_audiences = [token_audiences]

                # Check if any token audience is in required audiences
                if not any(aud in required_audiences for aud in token_audiences):
                    self.logger.warning(
                        f"Token audience mismatch. Required: {required_audiences}, Got: {token_audiences}"
                    )
                    return {
                        "valid": False,
                        "error": f"Invalid audience. Required one of: {required_audiences}, Got: {token_audiences}",
                    }

            # Additional security checks
            current_time = int(time.time())

            # Check token age (not too old even if not expired)
            if payload.get("iat", 0) < current_time - (24 * 3600):  # Max 24 hours old
                return {"valid": False, "error": "Token too old"}

            # Check if token is not from the future
            if payload.get("iat", 0) > current_time + 300:  # 5 minute tolerance
                return {"valid": False, "error": "Token issued in future"}

            self.logger.debug(f"Token validation successful for user: {payload.get('sub')}")
            return {"valid": True, "payload": payload}

        except jwt.ExpiredSignatureError:
            self.logger.warning("Token validation failed: Token has expired")
            return {"valid": False, "error": "Token has expired"}
        except jwt.InvalidIssuerError:
            self.logger.warning(f"Token validation failed: Invalid issuer (expected: {self.issuer})")
            return {"valid": False, "error": f"Invalid issuer (expected: {self.issuer})"}
        except jwt.InvalidSignatureError:
            self.logger.warning("Token validation failed: Invalid token signature")
            return {"valid": False, "error": "Invalid token signature"}
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Token validation failed: Invalid token: {str(e)}")
            return {"valid": False, "error": f"Invalid token: {str(e)}"}
        except Exception as e:
            self.logger.error(f"Token verification failed with unexpected error: {e}")
            return {"valid": False, "error": f"Token verification failed: {str(e)}"}

    # Alias for compatibility
    def verify_token(self, token, valid_audiences=None):
        """Alias for validate_token for backward compatibility"""
        return self.validate_token(token, valid_audiences)


class AuthenticationManager:
    """High-level authentication management"""

    def __init__(self, jwt_validator):
        self.jwt_validator = jwt_validator
        self.logger = logging.getLogger(__name__)

    def authenticate_request(self, headers, path_config):
        """
        Authenticate a request based on headers and path configuration

        Args:
            headers (dict): Request headers
            path_config (dict): Path configuration from config

        Returns:
            dict: Authentication result
        """
        if not path_config.get("require_bearer", False):
            return {"valid": True, "payload": None}

        auth_header = headers.get("Authorization")
        if not auth_header:
            self.logger.warning("Authentication failed: Missing Authorization header")
            return {"valid": False, "error": "Missing Authorization header"}

        if not auth_header.startswith("Bearer "):
            self.logger.warning("Authentication failed: Invalid Authorization header format")
            return {"valid": False, "error": "Invalid Authorization header format"}

        token = auth_header[7:]  # Remove "Bearer " prefix
        valid_audiences = path_config.get("valid_audiences")

        result = self.jwt_validator.validate_token(token, valid_audiences)

        if result["valid"]:
            user_id = result["payload"].get("sub", "unknown")
            self.logger.info(f"Authentication successful for user: {user_id}")
        else:
            self.logger.warning(f"Authentication failed: {result['error']}")

        return result


def load_jwt_keys(public_key_path, private_key_path=None):
    """Load JWT public and private keys with proper error handling"""
    try:
        # Load public key
        try:
            with open(public_key_path, "r") as key_file:
                public_key = key_file.read()
        except FileNotFoundError:
            logging.error(f"JWT public key file not found: {public_key_path}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading JWT public key: {e}")
            sys.exit(1)

        # Validate public key format (skip validation if it's a mock for testing)
        if not hasattr(public_key, "__call__") and isinstance(public_key, str):
            try:
                # Try to load the key to validate format
                from cryptography.hazmat.primitives import serialization

                serialization.load_pem_public_key(public_key.encode())
            except Exception as e:
                logging.error(f"Invalid JWT public key format: {e}")
                sys.exit(1)

        logging.info(f"Loaded JWT public key: {public_key_path}")

        # Load private key if provided (for token generation)
        private_key = None
        if private_key_path:
            try:
                with open(private_key_path, "r") as key_file:
                    private_key = key_file.read()
                logging.info(f"Loaded JWT private key: {private_key_path}")
            except FileNotFoundError:
                logging.error(f"JWT private key file not found: {private_key_path}")
                sys.exit(1)
            except Exception as e:
                logging.error(f"Error reading JWT private key: {e}")
                sys.exit(1)

        return public_key, private_key

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"Unexpected error loading JWT keys: {e}")
        sys.exit(1)
