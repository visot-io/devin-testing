#!/usr/bin/env python3
"""
API module for Gitleaks Python implementation.

This module provides functions for scanning GitHub repositories
and generating reports.
"""

import os
import sys
import json
import configparser
from typing import Dict, List, Optional, Union, Any, Tuple
import subprocess
import tempfile
import shutil

# Try to import GitPython
try:
    import git
    GITPYTHON_AVAILABLE = True
except ImportError:
    GITPYTHON_AVAILABLE = False


def load_github_config(config_path: Optional[str] = None) -> Dict[str, str]:
    """
    Load GitHub configuration from config.ini.
    
    Args:
        config_path: Path to config.ini file
        
    Returns:
        Dictionary with GitHub configuration
    """
    # Default configuration
    config = {
        "token": "",
        "repo": "",
        "owner": ""
    }
    
    # Try to find config.ini
    if not config_path:
        # Check current directory
        if os.path.exists("config.ini"):
            config_path = "config.ini"
        # Check script directory
        elif os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")):
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
    
    # Load configuration if found
    if config_path and os.path.exists(config_path):
        parser = configparser.ConfigParser()
        parser.read(config_path)
        
        if "GitHub" in parser:
            if "token" in parser["GitHub"]:
                config["token"] = parser["GitHub"]["token"]
            if "repo" in parser["GitHub"]:
                config["repo"] = parser["GitHub"]["repo"]
            if "owner" in parser["GitHub"]:
                config["owner"] = parser["GitHub"]["owner"]
    
    return config


def clone_repository(repo_url: str, target_dir: str, token: Optional[str] = None) -> bool:
    """
    Clone a GitHub repository.
    
    Args:
        repo_url: URL of the repository to clone
        target_dir: Directory to clone the repository to
        token: GitHub token for authentication
        
    Returns:
        True if successful, False otherwise
    """
    # Check if GitPython is available
    if GITPYTHON_AVAILABLE:
        try:
            # Add token to URL if provided
            if token:
                # Extract the protocol and the rest of the URL
                protocol, rest = repo_url.split("://", 1)
                # Insert the token
                auth_url = f"{protocol}://{token}@{rest}"
            else:
                auth_url = repo_url
            
            # Clone the repository
            git.Repo.clone_from(auth_url, target_dir)
            return True
        except Exception as e:
            print(f"Error cloning repository with GitPython: {e}")
            return False
    else:
        try:
            # Add token to URL if provided
            if token:
                # Extract the protocol and the rest of the URL
                protocol, rest = repo_url.split("://", 1)
                # Insert the token
                auth_url = f"{protocol}://{token}@{rest}"
            else:
                auth_url = repo_url
            
            # Clone the repository using git command
            subprocess.run(
                ["git", "clone", auth_url, target_dir],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error cloning repository with git command: {e}")
            return False


def scan_repository(
    repo_url: Optional[str] = None,
    target_dir: Optional[str] = None,
    token: Optional[str] = None,
    config_path: Optional[str] = None,
    verbose: bool = False
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Scan a GitHub repository for secrets.
    
    Args:
        repo_url: URL of the repository to scan
        target_dir: Directory to scan
        token: GitHub token for authentication
        config_path: Path to gitleaks.toml configuration file
        verbose: Whether to show verbose output
        
    Returns:
        Tuple of (findings, error)
    """
    # Import here to avoid circular imports
    from detect.git import GitScanner
    from detect.detector import Detector
    from config.config import load_config
    import os
    
    # Load GitHub configuration if not provided
    if not repo_url or not token:
        github_config = load_github_config()
        
        if not repo_url and github_config["repo"]:
            # Construct repo URL from config
            owner = github_config["owner"]
            repo = github_config["repo"].split("/")[-1] if "/" in github_config["repo"] else github_config["repo"]
            repo_url = f"https://github.com/{owner}/{repo}.git"
        
        if not token and github_config["token"]:
            token = github_config["token"]
    
    # Check if we have a repository URL
    if not repo_url and not target_dir:
        return [], "No repository URL or target directory provided"
    
    # Create a temporary directory if target_dir is not provided
    temp_dir = None
    if not target_dir:
        temp_dir = tempfile.mkdtemp()
        target_dir = temp_dir
    
    try:
        # Clone the repository if it doesn't exist
        if repo_url and not os.path.exists(target_dir):
            if verbose:
                print(f"Cloning repository {repo_url} to {target_dir}")
            
            success = clone_repository(repo_url, target_dir, token)
            if not success:
                return [], f"Failed to clone repository {repo_url}"
        
        # Load configuration
        config = load_config(config_path)
        config.verbose = verbose
        
        # Create a scanner
        scanner = GitScanner(config)
        
        # Scan the repository
        if verbose:
            print(f"Scanning repository in {target_dir}")
        
        findings = scanner.scan(target_dir)
        
        # If no findings and not a Git repository, try content scanning
        if not findings and not os.path.exists(os.path.join(target_dir, ".git")):
            if verbose:
                print(f"{target_dir} is not a Git repository, falling back to content scanning")
            
            # Create a detector for content scanning
            detector = Detector(config)
            
            # Scan files in the directory
            content_findings = []
            for root, _, files in os.walk(target_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        file_findings = detector.scan_content(content, file_path)
                        content_findings.extend(file_findings)
                    except Exception as e:
                        if verbose:
                            print(f"Error scanning file {file_path}: {e}")
            
            findings = content_findings
        
        return findings, None
    
    except Exception as e:
        return [], f"Error scanning repository: {e}"
    
    finally:
        # Clean up temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)


def generate_report(
    findings: List[Dict[str, Any]],
    output_format: str = "json",
    output_file: Optional[str] = None,
    redact: bool = False
) -> Optional[str]:
    """
    Generate a report from findings.
    
    Args:
        findings: List of findings
        output_format: Output format (json, csv, sarif, junit)
        output_file: Output file path
        redact: Whether to redact secrets
        
    Returns:
        Report as string if output_file is None, None otherwise
    """
    # Import here to avoid circular imports
    from report.finding import Finding
    
    # Convert findings to Finding objects
    finding_objects = []
    for finding in findings:
        finding_objects.append(Finding(**finding))
    
    # Create a reporter
    if output_format == "json":
        from report.json import JSONReporter
        reporter = JSONReporter(redact=redact)
    elif output_format == "csv":
        from report.csv import CSVReporter
        reporter = CSVReporter(redact=redact)
    elif output_format == "sarif":
        from report.sarif import SARIFReporter
        reporter = SARIFReporter(redact=redact)
    elif output_format == "junit":
        from report.junit import JUnitReporter
        reporter = JUnitReporter(redact=redact)
    else:
        return f"Unsupported output format: {output_format}"
    
    # Generate report
    if output_file:
        with open(output_file, "w") as f:
            reporter.write(f, finding_objects)
        return None
    else:
        import io
        output = io.StringIO()
        reporter.write(output, finding_objects)
        return output.getvalue() if output.getvalue() else "[]"


if __name__ == "__main__":
    # Example usage
    findings, error = scan_repository(verbose=True)
    
    if error:
        print(f"Error: {error}")
        sys.exit(1)
    
    # Generate report
    report = generate_report(findings, output_format="json")
    print(report)
