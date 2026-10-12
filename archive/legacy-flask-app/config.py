"""
Simple configuration management for environment variables.
Loads from .env file and provides basic access functions.
"""

import os
from typing import Any, Optional
from dotenv import load_dotenv

# Global configuration store
_config = {}
_loaded = False


def load_config() -> None:
    """Load configuration from .env file and environment variables."""
    global _config, _loaded
    
    if _loaded:
        return
    
    # Load from .env file if it exists
    load_dotenv()
    
    # Load all environment variables into config
    _config = dict(os.environ)
    
    # Basic validation for required keys
    required_keys = ['DEEPSEEK_API_KEY']
    missing_keys = [key for key in required_keys if not _config.get(key)]
    
    if missing_keys:
        print(f"Warning: Missing required environment variables: {missing_keys}")
    
    _loaded = True


def get_config(key: str, default: Any = None) -> Any:
    """
    Get configuration value by key.
    
    Args:
        key: Configuration key to retrieve
        default: Default value if key not found
        
    Returns:
        Configuration value or default
    """
    if not _loaded:
        load_config()
    
    return _config.get(key, default)


def reload_config() -> None:
    """Reload configuration from environment."""
    global _loaded
    _loaded = False
    load_config()