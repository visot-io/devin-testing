class Config:
    def __init__(self, config_path=None):
        self.config_path = config_path
    
    def get_github_config(self):
        """Mock getting GitHub configuration."""
        return {
            "repo": "visot-io/devin-testing",
            "token": "mock-token",
            "branch": "main"
        }
    
    def get_scan_config(self):
        """Mock getting scan configuration."""
        return {
            "rules": ["generic-api-key", "aws-access-key", "password-in-code"],
            "exclude_paths": ["node_modules", "dist"],
            "exclude_commits": []
        }
