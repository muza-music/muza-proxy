"""
Tests for utility scripts
"""

import pytest
import jwt
import time
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, mock_open


class TestSignUtility:
    """Test the sign.py utility"""
    
    def test_sign_basic_token(self, test_rsa_keys, temp_dir):
        """Test basic token signing"""
        # Import the sign module
        utils_path = Path(__file__).parent.parent / "utils"
        sys.path.insert(0, str(utils_path))
        
        from sign import sign_token
        
        token = sign_token(
            test_rsa_keys["private_key"],
            "test_user",
            expires_in_hours=24,
            issuer="muza-proxy",
            audience="proxy-client"
        )
        
        # Verify the token can be decoded
        payload = jwt.decode(
            token,
            test_rsa_keys["public_key"],
            algorithms=["RS256"],
            audience="proxy-client",
            issuer="muza-proxy"
        )
        
        assert payload["sub"] == "test_user"
        assert payload["aud"] == "proxy-client"
        assert payload["iss"] == "muza-proxy"
    
    def test_sign_with_multiple_audiences(self, test_rsa_keys):
        """Test signing token with multiple audiences"""
        utils_path = Path(__file__).parent.parent / "utils"
        sys.path.insert(0, str(utils_path))
        
        from sign import sign_token
        
        token = sign_token(
            test_rsa_keys["private_key"],
            "multi_user",
            audience="user,admin"
        )
        
        payload = jwt.decode(
            token,
            test_rsa_keys["public_key"],
            algorithms=["RS256"],
            options={"verify_aud": False}  # Skip audience verification for this test
        )
        
        assert payload["sub"] == "multi_user"
        assert payload["aud"] == ["user", "admin"]
    
    def test_sign_custom_expiration(self, test_rsa_keys):
        """Test signing token with custom expiration"""
        utils_path = Path(__file__).parent.parent / "utils"
        sys.path.insert(0, str(utils_path))
        
        from sign import sign_token
        
        token = sign_token(
            test_rsa_keys["private_key"],
            "short_lived_user",
            expires_in_hours=1
        )
        
        payload = jwt.decode(
            token,
            test_rsa_keys["public_key"],
            algorithms=["RS256"],
            options={"verify_aud": False}
        )
        
        # Check that expiration is approximately 1 hour from now
        current_time = int(time.time())
        expected_exp = current_time + 3600  # 1 hour
        assert abs(payload["exp"] - expected_exp) < 60  # Within 1 minute


class TestVerifyUtility:
    """Test the verify.py utility"""
    
    def test_verify_valid_token(self, test_rsa_keys, sample_jwt_token):
        """Test verifying a valid token"""
        utils_path = Path(__file__).parent.parent / "utils"
        sys.path.insert(0, str(utils_path))
        
        from verify import verify_token
        
        result = verify_token(
            sample_jwt_token["token"],
            test_rsa_keys["public_key"],
            issuer="muza-proxy",
            audience="user"
        )
        
        assert result["status"] == "valid"
        assert result["payload"]["sub"] == "test_user"
    
    def test_verify_expired_token(self, test_rsa_keys, expired_jwt_token):
        """Test verifying an expired token"""
        utils_path = Path(__file__).parent.parent / "utils"
        sys.path.insert(0, str(utils_path))
        
        from verify import verify_token
        
        result = verify_token(
            expired_jwt_token["token"],
            test_rsa_keys["public_key"],
            issuer="muza-proxy",
            audience="user"
        )
        
        assert result["status"] == "error"
        assert "expired" in result["error"].lower()
    
    def test_verify_invalid_audience(self, test_rsa_keys, sample_jwt_token):
        """Test verifying token with wrong audience"""
        utils_path = Path(__file__).parent.parent / "utils"
        sys.path.insert(0, str(utils_path))
        
        from verify import verify_token
        
        result = verify_token(
            sample_jwt_token["token"],
            test_rsa_keys["public_key"],
            issuer="muza-proxy",
            audience="admin"  # Token has "user" audience
        )
        
        assert result["status"] == "error"
        assert "audience" in result["error"].lower()
    
    def test_verify_any_audience(self, test_rsa_keys, sample_jwt_token):
        """Test verifying token with any audience"""
        utils_path = Path(__file__).parent.parent / "utils"
        sys.path.insert(0, str(utils_path))
        
        from verify import verify_token
        
        result = verify_token(
            sample_jwt_token["token"],
            test_rsa_keys["public_key"],
            issuer="muza-proxy",
            audience=None
        )
        
        assert result["status"] == "valid"
        assert result["payload"]["sub"] == "test_user"


class TestUtilityScripts:
    """Test utility scripts as command-line tools"""
    
    def test_sign_script_execution(self, test_rsa_keys):
        """Test running sign.py as a script"""
        script_path = Path(__file__).parent.parent / "utils" / "sign.py"
        
        result = subprocess.run([
            sys.executable, str(script_path),
            test_rsa_keys["private_key_path"],
            "cli_test_user",
            "--audience", "test-audience",
            "--expires", "1"
        ], capture_output=True, text=True)
        
        assert result.returncode == 0
        assert "Bearer token" in result.stdout
        assert "cli_test_user" in result.stdout
    
    def test_verify_script_execution(self, test_rsa_keys, sample_jwt_token):
        """Test running verify.py as a script"""
        script_path = Path(__file__).parent.parent / "utils" / "verify.py"
        
        result = subprocess.run([
            sys.executable, str(script_path),
            sample_jwt_token["token"],
            test_rsa_keys["public_key_path"],
            "--audience", "user"
        ], capture_output=True, text=True)
        
        assert result.returncode == 0
        assert "Token is VALID" in result.stdout
        assert "test_user" in result.stdout
    
    def test_verify_script_json_output(self, test_rsa_keys, sample_jwt_token):
        """Test verify.py JSON output"""
        script_path = Path(__file__).parent.parent / "utils" / "verify.py"
        
        result = subprocess.run([
            sys.executable, str(script_path),
            sample_jwt_token["token"],
            test_rsa_keys["public_key_path"],
            "--audience", "user",
            "--json"
        ], capture_output=True, text=True)
        
        assert result.returncode == 0
        
        import json
        output = json.loads(result.stdout)
        assert output["status"] == "valid"
        assert output["payload"]["sub"] == "test_user"
    
    def test_sign_script_invalid_key(self):
        """Test sign.py with invalid key file"""
        script_path = Path(__file__).parent.parent / "utils" / "sign.py"
        
        result = subprocess.run([
            sys.executable, str(script_path),
            "nonexistent_key.pem",
            "test_user"
        ], capture_output=True, text=True)
        
        assert result.returncode == 1
        assert "does not exist" in result.stderr.lower()
    
    def test_verify_script_invalid_token(self, test_rsa_keys):
        """Test verify.py with invalid token"""
        script_path = Path(__file__).parent.parent / "utils" / "verify.py"
        
        result = subprocess.run([
            sys.executable, str(script_path),
            "invalid.token.here",
            test_rsa_keys["public_key_path"]
        ], capture_output=True, text=True)
        
        assert result.returncode == 1
        assert "Token is INVALID" in result.stdout
