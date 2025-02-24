from typing import List, Generator, Optional
import tempfile
import subprocess
from pathlib import Path
import os
try:
    # Try relative imports first (for module usage)
    from ..models.rules import Rule
    from ..models.findings import Finding
    from ..core.scanner import Scanner
except ImportError:
    # Fall back to absolute imports (for direct file execution)
    from app.models.rules import Rule
    from app.models.findings import Finding
    from app.core.scanner import Scanner
try:
    import git
except ImportError:
    raise ImportError("GitPython package is required. Install it using: pip install GitPython")

class GitScanner:
    def __init__(self, rules: List[Rule]):
        self.rules = rules
        self.scanner = Scanner(rules)

    def _clone_repository(self, repo_url: str, token: Optional[str] = None) -> Path:
        """Clone a repository to a temporary directory."""
        temp_dir = tempfile.mkdtemp()
        try:
            # Use token in URL if provided
            if token:
                auth_url = repo_url.replace("https://", f"https://oauth2:{token}@")
            else:
                auth_url = repo_url

            # Clone repository
            repo = git.Repo.clone_from(auth_url, temp_dir)
            return Path(temp_dir)
        except Exception as e:
            # Clean up on error
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)
            raise

    def scan_repository(self, repo_url: str, log_opts: str = "", token: Optional[str] = None) -> Generator[Finding, None, None]:
        """Scan a git repository for secrets."""
        repo_path = None
        try:
            # Clone repository
            repo_path = self._clone_repository(repo_url, token)

            # Get repository information
            repo = git.Repo(repo_path)
            commit = repo.head.commit

            # Prepare commit info
            commit_info = {
                'commit': commit.hexsha,
                'author': commit.author.name,
                'email': commit.author.email,
                'date': commit.authored_datetime.isoformat(),
                'message': commit.message.strip(),
                'repo': '/'.join(repo_url.split('/')[-2:]).replace('.git', '')
            }

            # Scan all files in repository
            findings = []
            for root, _, files in os.walk(repo_path):
                for file in files:
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(repo_path)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Use scanner to find secrets
                            for finding in self.scanner.scan_content(
                                content,
                                path=str(rel_path),
                                commit_info=commit_info
                            ):
                                findings.append(finding)
                                yield finding
                    except UnicodeDecodeError:
                        # Skip binary files
                        continue
                        
        except Exception as e:
            print(f"Error scanning repository: {str(e)}")
            raise
        finally:
            # Clean up temporary directory
            if repo_path and os.path.exists(repo_path):
                import shutil
                shutil.rmtree(repo_path)
