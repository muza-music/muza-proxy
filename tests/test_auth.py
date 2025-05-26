"""
Tests for JWT authentication
"""

import pytest
import jwt
import time
from unittest.mock import patch, mock_open, MagicMock

# Import from the correct module path
from src.auth import JWTValidator, load_jwt_keys


class TestJWTValidator:
    """Test JWTValidator class"""
    
    def test_init_with_public_key(self, test_rsa_keys):
        """Test initializing validator with public key"""
        validator = JWTValidator(test_rsa_keys["public_key"])
        assert validator.public_key == test_rsa_keys["public_key"]
        assert validator.enabled is True
    
    def test_init_without_public_key(self):
        """Test initializing validator without public key"""
        validator = JWTValidator(None)
        assert validator.public_key is None
        assert validator.enabled is False
    
    def test_validate_valid_token(self, test_rsa_keys, sample_jwt_token):
        """Test validating a valid JWT token"""
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        result = validator.validate_token(sample_jwt_token["token"])
        
        assert result["valid"] is True
        assert result["payload"]["sub"] == "test_user"
        assert result["payload"]["aud"] == "user"
    
    def test_validate_expired_token(self, test_rsa_keys, expired_jwt_token):
        """Test validating an expired JWT token"""
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        result = validator.validate_token(expired_jwt_token["token"])
        
        assert result["valid"] is False
        assert "expired" in result["error"].lower()
    
    def test_validate_invalid_signature(self, test_rsa_keys, sample_jwt_token):
        """Test validating token with invalid signature"""
        # Create validator with different public key
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        different_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        different_public_pem = different_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        validator = JWTValidator(different_public_pem)
        
        result = validator.validate_token(sample_jwt_token["token"])
        
        assert result["valid"] is False
        assert "signature" in result["error"].lower()
    
    def test_validate_malformed_token(self, test_rsa_keys):
        """Test validating a malformed token"""
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        result = validator.validate_token("not.a.valid.jwt.token")
        
        assert result["valid"] is False
        assert "invalid" in result["error"].lower()
    
    def test_validate_without_public_key(self, sample_jwt_token):
        """Test validating token when validator is disabled"""
        validator = JWTValidator(None)
        
        result = validator.validate_token(sample_jwt_token["token"])
        
        assert result["valid"] is False
        assert "disabled" in result["error"].lower()
    
    def test_check_audience_valid(self, test_rsa_keys, sample_jwt_token):
        """Test audience validation with valid audience"""
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        result = validator.validate_token(
            sample_jwt_token["token"],
            required_audiences=["user", "admin"]
        )
        
        assert result["valid"] is True
    
    def test_check_audience_invalid(self, test_rsa_keys, sample_jwt_token):
        """Test audience validation with invalid audience"""
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        result = validator.validate_token(
            sample_jwt_token["token"],
            required_audiences=["admin"]  # Token has "user" audience
        )
        
        assert result["valid"] is False
        assert "audience" in result["error"].lower()
    
    def test_check_audience_multiple_valid(self, test_rsa_keys):
        """Test token with multiple audiences"""
        # Create token with multiple audiences
        payload = {
            "iss": "muza-proxy",
            "sub": "test_user",
            "aud": ["user", "admin"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time())
        }
        
        token = jwt.encode(payload, test_rsa_keys["private_key"], algorithm="RS256")
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        # Should be valid for either audience
        result1 = validator.validate_token(token, required_audiences=["user"])
        result2 = validator.validate_token(token, required_audiences=["admin"])
        result3 = validator.validate_token(token, required_audiences=["staff"])
        
        assert result1["valid"] is True
        assert result2["valid"] is True
        assert result3["valid"] is False


class TestLoadJWTKeys:
    """Test JWT key loading functions"""
    
    def test_load_keys_both_provided(self, test_rsa_keys):
        """Test loading both public and private keys"""
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
                test_rsa_keys["public_key_path"],
                test_rsa_keys["private_key_path"]
            )
            
            assert public_key == test_rsa_keys["public_key"]
            assert private_key == test_rsa_keys["private_key"]
    
    def test_load_keys_public_only(self, test_rsa_keys):
        """Test loading only public key"""
        def mock_open_side_effect(filename, mode='r'):
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=None)
            mock_file.read.return_value = test_rsa_keys["public_key"]
            return mock_file
        
        with patch("builtins.open", side_effect=mock_open_side_effect):
            public_key, private_key = load_jwt_keys(
                test_rsa_keys["public_key_path"],
                None
            )
            
            assert public_key == test_rsa_keys["public_key"]
            assert private_key is None
    
    def test_load_keys_file_not_found(self):
        """Test loading keys when file doesn't exist"""
        with pytest.raises(SystemExit):
            load_jwt_keys("nonexistent_public.pem", "nonexistent_private.pem")
    
    def test_load_keys_invalid_format(self):
        """Test loading keys with invalid format"""
        with patch("builtins.open", mock_open(read_data="invalid key content")):
            with pytest.raises(SystemExit):
                load_jwt_keys("invalid_public.pem", None)


class TestAuthenticationIntegration:
    """Integration tests for authentication flow"""
    
    def test_full_authentication_flow(self, test_rsa_keys):
        """Test complete authentication flow"""
        # Create validator
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        # Create token
        payload = {
            "iss": "muza-proxy",
            "sub": "integration_test_user",
            "aud": "api-client",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time())
        }
        
        token = jwt.encode(payload, test_rsa_keys["private_key"], algorithm="RS256")
        
        # Validate token
        result = validator.validate_token(token, required_audiences=["api-client"])
        
        assert result["valid"] is True
        assert result["payload"]["sub"] == "integration_test_user"
        assert result["payload"]["aud"] == "api-client"
    
    def test_authentication_with_custom_claims(self, test_rsa_keys):
        """Test authentication with custom claims"""
        validator = JWTValidator(test_rsa_keys["public_key"])
        
        # Create token with custom claims
        payload = {
            "iss": "muza-proxy",
            "sub": "test_user",
            "aud": "user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time()),
            "role": "admin",
            "permissions": ["read", "write"]
        }
        
        token = jwt.encode(payload, test_rsa_keys["private_key"], algorithm="RS256")
        result = validator.validate_token(token, required_audiences=["user"])
        
        assert result["valid"] is True
        assert result["payload"]["role"] == "admin"
        assert result["payload"]["permissions"] == ["read", "write"]
