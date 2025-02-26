import time
import random
import string
import uuid

class Scanner:
    def __init__(self, config_path=None):
        self.config_path = config_path
    
    def _generate_mock_finding(self, path="test.txt"):
        """Generate a mock finding for testing purposes."""
        rule_ids = ["generic-api-key", "aws-access-key", "password-in-code", "database-connection-string"]
        descriptions = {
            "generic-api-key": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
            "aws-access-key": "AWS Access Key detected, which could grant access to AWS services and resources.",
            "password-in-code": "Password in Code",
            "database-connection-string": "Database Connection String"
        }
        
        rule_id = random.choice(rule_ids)
        secret = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
        
        return {
            "rule_id": rule_id,
            "description": descriptions[rule_id],
            "file": path,
            "match": f"API_KEY=\"{secret}\"",
            "secret": secret,
            "start_line": random.randint(1, 100),
            "end_line": random.randint(1, 100),
            "start_column": random.randint(1, 50),
            "end_column": random.randint(51, 100),
            "entropy": round(random.uniform(3.5, 4.5), 2),
            "author": None,
            "commit": None,
            "date": None,
            "email": None,
            "message": None,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f"),
            "fingerprint": str(uuid.uuid4().hex)
        }
    
    def scan_repo(self, repo_url=None, branch=None):
        """Mock scanning a repository."""
        # Simulate processing time
        time.sleep(0.5)
        
        # Generate 1-3 random findings
        num_findings = random.randint(1, 3)
        findings = [self._generate_mock_finding("repo/file.txt") for _ in range(num_findings)]
        
        return {
            "findings": findings,
            "scan_duration": round(random.uniform(0.5, 2.0), 2),
            "status": "success",
            "error_message": None
        }
    
    def scan_file(self, file_path):
        """Mock scanning a file."""
        # Simulate processing time
        time.sleep(0.2)
        
        # Generate 0-2 random findings
        num_findings = random.randint(0, 2)
        findings = [self._generate_mock_finding(file_path) for _ in range(num_findings)]
        
        return {
            "findings": findings,
            "scan_duration": round(random.uniform(0.1, 1.0), 2),
            "status": "success",
            "error_message": None
        }
    
    def scan_content(self, content, path="content.txt"):
        """Mock scanning content."""
        # Simulate processing time
        time.sleep(0.1)
        
        # Check if content contains API_KEY or similar patterns
        if "API_KEY" in content or "SECRET" in content or "PASSWORD" in content:
            # Generate 1-2 findings
            num_findings = random.randint(1, 2)
            findings = [self._generate_mock_finding(path) for _ in range(num_findings)]
        else:
            # No findings
            findings = []
        
        return {
            "findings": findings,
            "scan_duration": round(random.uniform(0.05, 0.5), 2),
            "status": "success",
            "error_message": None
        }
