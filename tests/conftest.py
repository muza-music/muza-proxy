"""
Pytest configuration and shared fixtures for muza-proxy tests
"""

import pytest
import tempfile
import os
import jwt
import yaml
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def test_rsa_keys(temp_dir):
    """Generate RSA key pair for testing"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write keys to files
    private_key_path = temp_dir / "private_key.pem"
    public_key_path = temp_dir / "public_key.pem"
    
    private_key_path.write_bytes(private_pem)
    public_key_path.write_bytes(public_pem)
    
    return {
        "private_key": private_pem.decode(),
        "public_key": public_pem.decode(),
        "private_key_path": str(private_key_path),
        "public_key_path": str(public_key_path)
    }


@pytest.fixture
def sample_config():
    """Sample configuration for testing"""
    return {
        "default_server": "http://localhost:8080",
        "timeout": 30,
        "max_retries": 3,
        "log_level": "INFO",
        "proxy_paths": [
            {
                "path": "/api/public",
                "server": "http://public-api:3000",
                "require_bearer": False
            },
            {
                "path": "/api/user",
                "server": "http://user-api:3001",
                "require_bearer": True,
                "valid_audiences": ["user", "admin"]
            },
            {
                "path": "/api/admin",
                "server": "http://admin-api:4000",
                "require_bearer": True,
                "valid_audiences": ["admin"],
                "timeout": 60
            },
            {
                "path": "/health",
                "server": "http://health-service:3000",
                "require_bearer": False
            }
        ]
    }


@pytest.fixture
def config_file(temp_dir, sample_config):
    """Create a temporary config file"""
    config_path = temp_dir / "config.yaml"
    with open(config_path, 'w') as f:
        yaml.dump(sample_config, f)
    return str(config_path)


@pytest.fixture
def sample_jwt_token(test_rsa_keys):
    """Generate a sample JWT token for testing"""
    import time
    
    payload = {
        "iss": "muza-proxy",
        "sub": "test_user",
        "aud": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour
        "nbf": int(time.time())
    }
    
    token = jwt.encode(payload, test_rsa_keys["private_key"], algorithm="RS256")
    return {
        "token": token,
        "payload": payload
    }


@pytest.fixture
def expired_jwt_token(test_rsa_keys):
    """Generate an expired JWT token for testing"""
    import time
    
    payload = {
        "iss": "muza-proxy",
        "sub": "test_user",
        "aud": "user",
        "iat": int(time.time()) - 7200,  # 2 hours ago
        "exp": int(time.time()) - 3600,  # 1 hour ago (expired)
        "nbf": int(time.time()) - 7200
    }
    
    token = jwt.encode(payload, test_rsa_keys["private_key"], algorithm="RS256")
    return {
        "token": token,
        "payload": payload
    }
