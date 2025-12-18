import yaml
import os
from pathlib import Path

class Config:
    """Configuration management class"""

    def __init__(self, config_file='config.yaml'):
        self.config_file = config_file
        self._config = self._load_config()

    def _load_config(self):
        """Load YAML configuration file"""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Config file not found: {self.config_file}")

        with open(self.config_file, 'r') as f:
            return yaml.safe_load(f)

    def get(self, key, default=None):
        """
        Get configuration value by dot notation
        Example: config.get('server.host')
        """
        keys = key.split('.')
        value = self._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

        return value if value is not None else default

    # Convenience properties
    @property
    def server_host(self):
        return self.get('server.host', '0.0.0.0')

    @property
    def server_port(self):
        return self.get('server.port', 5000)

    @property
    def quorum(self):
        return self.get('consensus.quorum', 2)

    @property
    def total_monitors(self):
        return self.get('consensus.total_monitors', 3)

    @property
    def monitors(self):
        return self.get('monitors', [])

    @property
    def require_signatures(self):
        return self.get('security.require_signatures', True)

    @property
    def baseline_file(self):
        return self.get('storage.baseline_file', 'data/baseline.json')

    @property
    def log_file(self):
        return self.get('logging.file', 'logs/attest.log')

    @property
    def log_level(self):
        return self.get('logging.level', 'INFO')

# Global config instance
config = Config()
