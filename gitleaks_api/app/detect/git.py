"""
Git scanner module for Gitleaks Python implementation.

This module handles scanning Git repositories for secrets.
"""

import os
import sys
import re
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# Try to import GitPython
try:
    import git
    GITPYTHON_AVAILABLE = True
except ImportError:
    GITPYTHON_AVAILABLE = False

from detect.detector import Detector
from config.config import Config


class GitScanner:
    """Git scanner for scanning Git repositories."""
    
    def __init__(self, config: Config):
        """
        Initialize a new GitScanner.
        
        Args:
            config: Configuration to use
        """
        self.config = config
        self.detector = Detector(config)
    
    def scan(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Scan a Git repository for secrets.
        
        Args:
            repo_path: Path to the Git repository
            
        Returns:
            List of findings
        """
        # Check if the path exists
        if not os.path.exists(repo_path):
            print(f"Error: Repository path {repo_path} does not exist")
            return []
        
        # Check if the path is a Git repository
        if not os.path.exists(os.path.join(repo_path, ".git")):
            print(f"Warning: {repo_path} is not a Git repository, no Git scanning will be performed")
            return []
        
        # Scan the repository
        findings = []
        
        # Use GitPython if available
        if GITPYTHON_AVAILABLE:
            try:
                findings = self._scan_with_gitpython(repo_path)
            except Exception as e:
                print(f"Error scanning with GitPython: {e}")
                print("Falling back to git command")
                findings = self._scan_with_git_command(repo_path)
        else:
            findings = self._scan_with_git_command(repo_path)
        
        return findings
    
    def _scan_with_gitpython(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Scan a Git repository using GitPython.
        
        Args:
            repo_path: Path to the Git repository
            
        Returns:
            List of findings
        """
        findings = []
        
        # Open the repository
        repo = git.Repo(repo_path)
        
        # Get the default branch
        default_branch = repo.active_branch.name
        
        # Get all commits
        commits = list(repo.iter_commits(default_branch))
        
        # Scan each commit
        for commit in commits:
            # Get commit metadata
            commit_hash = commit.hexsha
            author = commit.author.name
            email = commit.author.email
            date = commit.authored_datetime.strftime("%Y-%m-%dT%H:%M:%S%z")
            message = commit.message
            
            # Get the diff
            if commit.parents:
                parent = commit.parents[0]
                diff = parent.diff(commit)
                
                # Scan each file in the diff
                for diff_item in diff:
                    # Skip binary files
                    if diff_item.a_blob and diff_item.a_blob.is_binary:
                        continue
                    
                    # Get the file path
                    file_path = diff_item.a_path
                    
                    # Get the file content
                    try:
                        content = diff_item.a_blob.data_stream.read().decode("utf-8")
                    except:
                        continue
                    
                    # Scan the content
                    file_findings = self.detector.scan_content(content, file_path)
                    
                    # Add commit metadata to findings
                    for finding in file_findings:
                        finding["Commit"] = commit_hash
                        finding["Author"] = author
                        finding["Email"] = email
                        finding["Date"] = date
                        finding["Message"] = message
                        finding["Link"] = self._generate_link(repo_path, commit_hash, file_path, finding["StartLine"])
                        finding["Fingerprint"] = self._generate_fingerprint(commit_hash, file_path, finding["RuleID"], finding["StartLine"])
                        
                        findings.append(finding)
        
        return findings
    
    def _scan_with_git_command(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Scan a Git repository using git command.
        
        Args:
            repo_path: Path to the Git repository
            
        Returns:
            List of findings
        """
        findings = []
        
        # Get the current directory
        current_dir = os.getcwd()
        
        try:
            # Change to the repository directory
            os.chdir(repo_path)
            
            # Get the default branch
            default_branch = self._get_default_branch()
            
            # Get all commits
            commits = self._get_commits(default_branch)
            
            # Scan each commit
            for commit in commits:
                # Get commit metadata
                commit_hash, author, email, date, message = self._get_commit_metadata(commit)
                
                # Get the files in the commit
                files = self._get_commit_files(commit)
                
                # Scan each file in the commit
                for file_path in files:
                    # Skip binary files
                    if self._is_binary_file(file_path, commit):
                        continue
                    
                    # Get the file content
                    content = self._get_file_content(file_path, commit)
                    
                    # Skip if content is empty
                    if not content:
                        continue
                    
                    # Scan the content
                    file_findings = self.detector.scan_content(content, file_path)
                    
                    # Add commit metadata to findings
                    for finding in file_findings:
                        finding["Commit"] = commit_hash
                        finding["Author"] = author
                        finding["Email"] = email
                        finding["Date"] = date
                        finding["Message"] = message
                        finding["Link"] = self._generate_link(repo_path, commit_hash, file_path, finding["StartLine"])
                        finding["Fingerprint"] = self._generate_fingerprint(commit_hash, file_path, finding["RuleID"], finding["StartLine"])
                        
                        findings.append(finding)
        
        finally:
            # Change back to the original directory
            os.chdir(current_dir)
        
        return findings
    
    def _get_default_branch(self) -> str:
        """
        Get the default branch of a Git repository.
        
        Returns:
            Default branch name
        """
        try:
            # Get the default branch
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return result.stdout.decode("utf-8").strip()
        except:
            # Default to main
            return "main"
    
    def _get_commits(self, branch: str) -> List[str]:
        """
        Get all commits in a branch.
        
        Args:
            branch: Branch name
            
        Returns:
            List of commit hashes
        """
        try:
            # Get all commits
            result = subprocess.run(
                ["git", "log", "--format=%H", branch],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return result.stdout.decode("utf-8").strip().split("\n")
        except:
            return []
    
    def _get_commit_metadata(self, commit: str) -> Tuple[str, str, str, str, str]:
        """
        Get metadata for a commit.
        
        Args:
            commit: Commit hash
            
        Returns:
            Tuple of (commit_hash, author, email, date, message)
        """
        try:
            # Get commit metadata
            result = subprocess.run(
                ["git", "show", "-s", "--format=%H%n%an%n%ae%n%aI%n%B", commit],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            lines = result.stdout.decode("utf-8").strip().split("\n")
            
            commit_hash = lines[0]
            author = lines[1]
            email = lines[2]
            date = lines[3]
            message = "\n".join(lines[4:])
            
            return commit_hash, author, email, date, message
        except:
            return commit, "", "", "", ""
    
    def _get_commit_files(self, commit: str) -> List[str]:
        """
        Get all files in a commit.
        
        Args:
            commit: Commit hash
            
        Returns:
            List of file paths
        """
        try:
            # Get all files
            result = subprocess.run(
                ["git", "ls-tree", "-r", "--name-only", commit],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return result.stdout.decode("utf-8").strip().split("\n")
        except:
            return []
    
    def _is_binary_file(self, file_path: str, commit: str) -> bool:
        """
        Check if a file is binary.
        
        Args:
            file_path: Path to the file
            commit: Commit hash
            
        Returns:
            True if the file is binary, False otherwise
        """
        try:
            # Check if the file is binary
            result = subprocess.run(
                ["git", "show", f"{commit}:{file_path}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Check for null bytes
            return b"\x00" in result.stdout
        except:
            return True
    
    def _get_file_content(self, file_path: str, commit: str) -> str:
        """
        Get the content of a file in a commit.
        
        Args:
            file_path: Path to the file
            commit: Commit hash
            
        Returns:
            File content
        """
        try:
            # Get the file content
            result = subprocess.run(
                ["git", "show", f"{commit}:{file_path}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return result.stdout.decode("utf-8")
        except:
            return ""
    
    def _generate_link(self, repo_path: str, commit: str, file_path: str, line: int) -> str:
        """
        Generate a link to a file in a commit.
        
        Args:
            repo_path: Path to the repository
            commit: Commit hash
            file_path: Path to the file
            line: Line number
            
        Returns:
            Link to the file
        """
        # Try to get the remote URL
        remote_url = self._get_remote_url(repo_path)
        
        if remote_url:
            # Convert SSH URL to HTTPS
            if remote_url.startswith("git@"):
                remote_url = remote_url.replace(":", "/").replace("git@", "https://")
            
            # Remove .git suffix
            if remote_url.endswith(".git"):
                remote_url = remote_url[:-4]
            
            return f"{remote_url}/blob/{commit}/{file_path}#{line}"
        
        return ""
    
    def _get_remote_url(self, repo_path: str) -> str:
        """
        Get the remote URL of a Git repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Remote URL
        """
        try:
            # Get the current directory
            current_dir = os.getcwd()
            
            # Change to the repository directory
            os.chdir(repo_path)
            
            # Get the remote URL
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Change back to the original directory
            os.chdir(current_dir)
            
            return result.stdout.decode("utf-8").strip()
        except:
            # Change back to the original directory
            os.chdir(current_dir)
            
            return ""
    
    def _generate_fingerprint(self, commit: str, file_path: str, rule_id: str, line: int) -> str:
        """
        Generate a fingerprint for a finding.
        
        Args:
            commit: Commit hash
            file_path: Path to the file
            rule_id: Rule ID
            line: Line number
            
        Returns:
            Fingerprint
        """
        return f"{commit}:{file_path}:{rule_id}:{line}"
