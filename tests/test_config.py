"""
Tests for configuration management
"""

import pytest
import yaml
import tempfile
from pathlib import Path

from config import ProxyConfig


class TestProxyConfig:
    """Test ProxyConfig class"""
    
    def test_load_valid_config(self, config_file, sample_config):
        """Test loading a valid configuration file"""
        config = ProxyConfig(config_file)
        
        assert config.get_default_server() == sample_config["default_server"]
        assert config.get_timeout() == sample_config["timeout"]
        assert config.get_max_retries() == sample_config["max_retries"]
        assert config.get_log_level() == sample_config["log_level"]
        assert len(config.get_proxy_paths()) == len(sample_config["proxy_paths"])
    
    def test_load_nonexistent_config(self):
        """Test loading a non-existent configuration file"""
        with pytest.raises(SystemExit):
            ProxyConfig("nonexistent.yaml")
    
    def test_load_invalid_yaml(self, temp_dir):
        """Test loading an invalid YAML file"""
        invalid_config = temp_dir / "invalid.yaml"
        invalid_config.write_text("invalid: yaml: content: [")
        
        with pytest.raises(SystemExit):
            ProxyConfig(str(invalid_config))
    
    def test_validate_valid_config(self, config_file):
        """Test validation of a valid configuration"""
        config = ProxyConfig(config_file)
        # Should not raise an exception
        config.validate_config()
    
    def test_validate_missing_default_server(self, temp_dir):
        """Test validation with missing default_server"""
        invalid_config = {
            "proxy_paths": [
                {"path": "/api", "server": "http://api:3000"}
            ]
        }
        
        config_path = temp_dir / "invalid.yaml"
        with open(config_path, 'w') as f:
            yaml.dump(invalid_config, f)
        
        config = ProxyConfig(str(config_path))
        with pytest.raises(ValueError, match="default_server is required"):
            config.validate_config()
    
    def test_validate_invalid_proxy_paths(self, temp_dir):
        """Test validation with invalid proxy paths"""
        invalid_config = {
            "default_server": "http://localhost:8080",
            "proxy_paths": [
                {"path": "/api"},  # Missing server
                {"server": "http://api:3000"},  # Missing path
                {
                    "path": "/admin",
                    "server": "http://admin:4000",
                    "valid_audiences": "not_a_list"  # Should be a list
                }
            ]
        }
        
        config_path = temp_dir / "invalid.yaml"
        with open(config_path, 'w') as f:
            yaml.dump(invalid_config, f)
        
        config = ProxyConfig(str(config_path))
        with pytest.raises(ValueError) as exc_info:
            config.validate_config()
        
        error_message = str(exc_info.value)
        assert "missing required 'server' field" in error_message
        assert "missing required 'path' field" in error_message
        assert "valid_audiences must be a list" in error_message
    
    def test_get_path_config_exact_match(self, config_file):
        """Test getting path configuration with exact match"""
        config = ProxyConfig(config_file)
        
        path_config = config.get_path_config("/api/public")
        assert path_config is not None
        assert path_config["path"] == "/api/public"
        assert path_config["server"] == "http://public-api:3000"
        assert path_config["require_bearer"] is False
    
    def test_get_path_config_prefix_match(self, config_file):
        """Test getting path configuration with prefix match"""
        config = ProxyConfig(config_file)
        
        path_config = config.get_path_config("/api/user/profile")
        assert path_config is not None
        assert path_config["path"] == "/api/user"
        assert path_config["server"] == "http://user-api:3001"
        assert path_config["require_bearer"] is True
    
    def test_get_path_config_longest_match(self, config_file):
        """Test that longest matching path is returned"""
        config = ProxyConfig(config_file)
        
        # Add a more specific path to test data
        config.config["proxy_paths"].append({
            "path": "/api/user/admin",
            "server": "http://user-admin:3002",
            "require_bearer": True
        })
        
        # Should match the more specific path
        path_config = config.get_path_config("/api/user/admin/settings")
        assert path_config["path"] == "/api/user/admin"
        assert path_config["server"] == "http://user-admin:3002"
    
    def test_get_path_config_no_match(self, config_file):
        """Test getting path configuration with no match"""
        config = ProxyConfig(config_file)
        
        path_config = config.get_path_config("/unknown/path")
        assert path_config is None
    
    def test_set_jwt_public_key(self, config_file):
        """Test setting JWT public key"""
        config = ProxyConfig(config_file)
        test_key = "test-public-key"
        
        config.set_jwt_public_key(test_key)
        assert config.jwt_public_key == test_key
    
    def test_reload_config(self, config_file, temp_dir):
        """Test reloading configuration"""
        config = ProxyConfig(config_file)
        original_server = config.get_default_server()
        
        # Modify the config file
        new_config = {
            "default_server": "http://new-server:9000",
            "proxy_paths": []
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(new_config, f)
        
        # Reload and verify changes
        config.reload_config()
        assert config.get_default_server() == "http://new-server:9000"
        assert config.get_default_server() != original_server


class TestConfigDefaults:
    """Test configuration default values"""
    
    def test_default_values(self, temp_dir):
        """Test that default values are returned when not specified"""
        minimal_config = {
            "default_server": "http://localhost:8080"
        }
        
        config_path = temp_dir / "minimal.yaml"
        with open(config_path, 'w') as f:
            yaml.dump(minimal_config, f)
        
        config = ProxyConfig(str(config_path))
        
        assert config.get_timeout() == 30
        assert config.get_max_retries() == 3
        assert config.get_log_level() == "INFO"
        assert config.get_proxy_paths() == []
