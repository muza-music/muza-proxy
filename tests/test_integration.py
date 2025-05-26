"""
Integration tests for muza-proxy
"""

import pytest
import tempfile
import yaml
import time
import jwt
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config import ProxyConfig
from auth import JWTValidator, load_jwt_keys


class TestConfigAuthIntegration:
    """Test integration between config and auth modules"""
    
    def test_config_with_auth_flow(self, config_file, test_rsa_keys):
        """Test complete config loading and auth setup"""
        # Load config
        config = ProxyConfig(config_file)
        config.validate_config()
        
        # Setup JWT validator
        config.set_jwt_public_key(test_rsa_keys["public_key"])
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        # Test token for protected endpoint
        payload = {
            "iss": "muza-proxy",
            "sub": "integration_user",
            "aud": "user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time())
        }
        
        token = jwt.encode(payload, test_rsa_keys["private_key"], algorithm="RS256")
        
        # Test path resolution and auth
        user_path_config = config.get_path_config("/api/user/profile")
        assert user_path_config is not None
        assert user_path_config["require_bearer"] is True
        assert "user" in user_path_config["valid_audiences"]
        
        # Validate token for this path
        result = validator.validate_token(token, user_path_config["valid_audiences"])
        assert result["valid"] is True
    
    def test_audience_based_access_control(self, config_file, test_rsa_keys):
        """Test audience-based access control"""
        config = ProxyConfig(config_file)
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        # Create tokens with different audiences
        user_token = jwt.encode({
            "iss": "muza-proxy",
            "sub": "user123",
            "aud": "user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time())
        }, test_rsa_keys["private_key"], algorithm="RS256")
        
        admin_token = jwt.encode({
            "iss": "muza-proxy",
            "sub": "admin456",
            "aud": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time())
        }, test_rsa_keys["private_key"], algorithm="RS256")
        
        # Test user access to user endpoints
        user_path = config.get_path_config("/api/user/data")
        user_result = validator.validate_token(user_token, user_path["valid_audiences"])
        assert user_result["valid"] is True
        
        # Test user access to admin endpoints (should fail)
        admin_path = config.get_path_config("/api/admin/settings")
        user_admin_result = validator.validate_token(user_token, admin_path["valid_audiences"])
        assert user_admin_result["valid"] is False
        
        # Test admin access to admin endpoints
        admin_result = validator.validate_token(admin_token, admin_path["valid_audiences"])
        assert admin_result["valid"] is True
        
        # Test admin access to user endpoints (admin should have access)
        admin_user_result = validator.validate_token(admin_token, user_path["valid_audiences"])
        assert admin_user_result["valid"] is True
    
    def test_public_endpoint_access(self, config_file, test_rsa_keys):
        """Test access to public endpoints"""
        config = ProxyConfig(config_file)
        
        # Public endpoints should not require authentication
        public_path = config.get_path_config("/api/public/info")
        assert public_path is not None
        assert public_path["require_bearer"] is False
        
        # Health check should also be public
        health_path = config.get_path_config("/health")
        assert health_path is not None
        assert health_path["require_bearer"] is False


class TestFullSystemIntegration:
    """Test full system integration scenarios"""
    
    def test_complete_request_flow(self, temp_dir, test_rsa_keys):
        """Test a complete request flow from config to response"""
        # Create a comprehensive config
        full_config = {
            "default_server": "http://default:8080",
            "timeout": 30,
            "max_retries": 3,
            "log_level": "INFO",
            "proxy_paths": [
                {
                    "path": "/api/v1/public",
                    "server": "http://public-service:3000",
                    "require_bearer": False,
                    "headers": {"X-Service": "public"}
                },
                {
                    "path": "/api/v1/user",
                    "server": "http://user-service:3001",
                    "require_bearer": True,
                    "valid_audiences": ["user", "admin"],
                    "timeout": 45,
                    "headers": {"X-Service": "user", "X-Auth": "required"}
                },
                {
                    "path": "/api/v1/admin",
                    "server": "http://admin-service:4000",
                    "require_bearer": True,
                    "valid_audiences": ["admin"],
                    "headers": {"X-Service": "admin", "X-Security": "high"}
                }
            ]
        }
        
        config_path = temp_dir / "full_config.yaml"
        with open(config_path, 'w') as f:
            yaml.dump(full_config, f)
        
        # Load and validate config
        config = ProxyConfig(str(config_path))
        config.validate_config()
        config.set_jwt_public_key(test_rsa_keys["public_key"])
        
        # Setup auth
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        # Test scenarios
        scenarios = [
            {
                "path": "/api/v1/public/status",
                "expected_config": {
                    "server": "http://public-service:3000",
                    "require_bearer": False,
                    "headers": {"X-Service": "public"}
                },
                "token_required": False
            },
            {
                "path": "/api/v1/user/profile",
                "expected_config": {
                    "server": "http://user-service:3001",
                    "require_bearer": True,
                    "valid_audiences": ["user", "admin"],
                    "timeout": 45,
                    "headers": {"X-Service": "user", "X-Auth": "required"}
                },
                "token_required": True,
                "valid_audiences": ["user"]
            },
            {
                "path": "/api/v1/admin/users",
                "expected_config": {
                    "server": "http://admin-service:4000",
                    "require_bearer": True,
                    "valid_audiences": ["admin"],
                    "headers": {"X-Service": "admin", "X-Security": "high"}
                },
                "token_required": True,
                "valid_audiences": ["admin"]
            }
        ]
        
        for scenario in scenarios:
            path_config = config.get_path_config(scenario["path"])
            assert path_config is not None
            
            # Verify path configuration
            for key, expected_value in scenario["expected_config"].items():
                assert path_config[key] == expected_value
            
            # Test authentication if required
            if scenario["token_required"]:
                # Create appropriate token
                token = jwt.encode({
                    "iss": "muza-proxy",
                    "sub": f"test_user_{scenario['valid_audiences'][0]}",
                    "aud": scenario["valid_audiences"][0],
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 3600,
                    "nbf": int(time.time())
                }, test_rsa_keys["private_key"], algorithm="RS256")
                
                result = validator.validate_token(
                    token, 
                    path_config.get("valid_audiences")
                )
                assert result["valid"] is True
    
    def test_error_handling_scenarios(self, temp_dir, test_rsa_keys):
        """Test various error handling scenarios"""
        # Invalid configuration scenarios
        invalid_configs = [
            {
                "name": "missing_default_server",
                "config": {"proxy_paths": []},
                "should_raise": True
            },
            {
                "name": "invalid_proxy_path",
                "config": {
                    "default_server": "http://test:8080",
                    "proxy_paths": [{"path": "/test"}]  # Missing server
                },
                "should_raise": True
            },
            {
                "name": "invalid_audiences",
                "config": {
                    "default_server": "http://test:8080",
                    "proxy_paths": [{
                        "path": "/test",
                        "server": "http://test:3000",
                        "valid_audiences": "not_a_list"
                    }]
                },
                "should_raise": True
            }
        ]
        
        for invalid_config in invalid_configs:
            config_path = temp_dir / f"{invalid_config['name']}.yaml"
            with open(config_path, 'w') as f:
                yaml.dump(invalid_config["config"], f)
            
            config = ProxyConfig(str(config_path))
            
            if invalid_config["should_raise"]:
                with pytest.raises(ValueError):
                    config.validate_config()
    
    def test_jwt_key_loading_integration(self, test_rsa_keys):
        """Test JWT key loading integration"""
        # Test successful key loading
        def mock_open_side_effect(filename, mode='r'):
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=None)
            
            if 'public' in filename:
                mock_file.read.return_value = test_rsa_keys["public_key"]
            else:
                mock_file.read.return_value = test_rsa_keys["private_key"]
            
            return mock_file
        
        with patch("builtins.open", side_effect=mock_open_side_effect):
            public_key, private_key = load_jwt_keys(
                "public.pem", "private.pem"
            )
            
            assert public_key == test_rsa_keys["public_key"]
            assert private_key == test_rsa_keys["private_key"]
        
        # Test validator creation with loaded keys
        validator = JWTValidator(public_key)
        assert validator.enabled is True
        assert validator.public_key == public_key
        
        # Test token validation with loaded keys
        token = jwt.encode({
            "iss": "muza-proxy",
            "sub": "key_test_user",
            "aud": "test",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time())
        }, test_rsa_keys["private_key"], algorithm="RS256")
        
        result = validator.validate_token(token, ["test"])
        assert result["valid"] is True
        assert result["payload"]["sub"] == "key_test_user"


class TestMakefileIntegration:
    """Test integration with Makefile commands"""
    
    def test_generate_and_verify_token_flow(self, test_rsa_keys):
        """Test the generate -> verify token flow"""
        # This simulates what the Makefile commands do
        utils_path = Path(__file__).parent.parent / "utils"
        sys.path.insert(0, str(utils_path))
        
        from sign import sign_token
        from verify import verify_token
        
        # Generate token (like make generate-token)
        token = sign_token(
            test_rsa_keys["private_key"],
            "makefile_test_user",
            expires_in_hours=24,
            audience="user"
        )
        
        # Verify token (like make verify-token)
        result = verify_token(
            token,
            test_rsa_keys["public_key"],
            issuer="muza-proxy",
            audience="user"
        )
        
        assert result["status"] == "valid"
        assert result["payload"]["sub"] == "makefile_test_user"
        assert result["payload"]["aud"] == "user"
    
    def test_config_validation_flow(self, config_file):
        """Test config validation flow (like make validate)"""
        # This simulates what make validate does
        config = ProxyConfig(config_file)
        
        # Should not raise any exceptions
        config.validate_config()
        
        # Verify that all expected configurations are present
        assert config.get_default_server() is not None
        assert len(config.get_proxy_paths()) > 0
        
        # Test specific path configurations
        user_path = config.get_path_config("/api/user/test")
        assert user_path is not None
        assert user_path["require_bearer"] is True
        
        public_path = config.get_path_config("/api/public/test")
        assert public_path is not None
        assert public_path["require_bearer"] is False
