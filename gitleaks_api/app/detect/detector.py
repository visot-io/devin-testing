"""
Detector module for Gitleaks Python implementation.

This module handles detecting secrets in content.
"""

import os
import sys
import re
import threading
from typing import List, Dict, Any, Optional, Pattern, Match, Tuple

from config.config import Config
from report.finding import Finding
from detect.fragment import Fragment


class Detector:
    """Detector for finding secrets in content."""
    
    def __init__(self, config: Config):
        """
        Initialize a new Detector.
        
        Args:
            config: Configuration to use
        """
        self.config = config
        self.compiled_rules = self._compile_rules()
        # Internal state
        self.findings = []
        self.finding_mutex = threading.Lock()
    
    def _compile_rules(self) -> Dict[str, Dict[str, Any]]:
        """
        Compile rules from configuration.
        
        Returns:
            Dictionary of compiled rules
        """
        compiled_rules = {}
        
        for rule in self.config.rules:
            # Skip disabled rules
            if not rule.Enabled:
                continue
            
            # Compile regex
            try:
                # Try to compile with re
                pattern = re.compile(rule.Regex)
                compiled_rules[rule.RuleID] = {
                    "pattern": pattern,
                    "description": rule.Description,
                    "keywords": [kw.lower() for kw in rule.Keywords] if rule.Keywords else [],
                    "entropy": rule.Entropy,
                    "secret_group": rule.SecretGroup,
                    "tags": rule.Tags
                }
                
                # Print success message if verbose
                if self.config.verbose:
                    print(f"Successfully compiled pattern for rule {rule.RuleID}")
            
            except re.error as e:
                # Print error message
                print(f"Error compiling regex for rule {rule.RuleID}: {e}")
                
                # Try to compile with regex module
                try:
                    import regex
                    pattern = regex.compile(rule.Regex)
                    compiled_rules[rule.RuleID] = {
                        "pattern": pattern,
                        "description": rule.Description,
                        "keywords": [kw.lower() for kw in rule.Keywords] if rule.Keywords else [],
                        "entropy": rule.Entropy,
                        "secret_group": rule.SecretGroup,
                        "tags": rule.Tags
                    }
                    
                    # Print success message if verbose
                    if self.config.verbose:
                        print(f"Successfully compiled pattern with regex module for rule {rule.RuleID}")
                
                except Exception as e:
                    # Print error message
                    print(f"Error compiling with regex module: {e}")
                    
                    # Try to compile a simplified pattern
                    try:
                        # Create a simplified pattern
                        simplified_pattern = r"\b[A-Za-z0-9+/]{32,}\b"
                        pattern = re.compile(simplified_pattern)
                        compiled_rules[rule.RuleID] = {
                            "pattern": pattern,
                            "description": rule.Description,
                            "keywords": [kw.lower() for kw in rule.Keywords] if rule.Keywords else [],
                            "entropy": rule.Entropy,
                            "secret_group": rule.SecretGroup,
                            "tags": rule.Tags
                        }
                        
                        # Print success message if verbose
                        if self.config.verbose:
                            print(f"Successfully compiled simplified pattern for rule {rule.RuleID}")
                    
                    except Exception as e:
                        # Print error message
                        print(f"Error compiling simplified pattern for rule {rule.RuleID}: {e}")
        
        return compiled_rules
        
    def detect(self, fragment: Fragment) -> List[Finding]:
        """
        Detect secrets in a fragment.
        
        Args:
            fragment: Fragment to detect secrets in
            
        Returns:
            List of findings
        """
        findings = []
        
        # Skip empty fragments
        if not fragment.raw:
            return findings
        
        # Apply rules
        for rule in self.config.rules:
            # Skip if no regex
            if not rule.Regex or not rule.Enabled:
                continue
            
            # Skip if path doesn't match
            if rule.Path and not rule.Path.search(fragment.file_path):
                continue
            
            # Skip if no keywords match (case-insensitive)
            if rule.Keywords and not any(kw.lower() in fragment.raw.lower() for kw in rule.Keywords):
                continue
            
            # Find matches
            pattern = None
            for rule_id, rule_data in self.compiled_rules.items():
                if rule_id == rule.RuleID:
                    pattern = rule_data["pattern"]
                    break
                    
            if not pattern:
                continue
                
            # Split content into lines for line-by-line scanning
            lines = fragment.raw.split('\n')
            for line_num, line in enumerate(lines, 1):
                # Skip empty lines
                if not line:
                    continue
                
                # Check if line is allowlisted
                if self._is_allowlisted(line):
                    continue
                    
                # Find matches in this line
                for match in pattern.finditer(line):
                    # Extract secret
                    if rule.SecretGroup > 0 and rule.SecretGroup <= len(match.groups()):
                        secret = match.group(rule.SecretGroup)
                    else:
                        secret = match.group(0)
                    
                    # Skip if secret is empty
                    if not secret:
                        continue
                    
                    # Create finding
                    finding = Finding(
                        RuleID=rule.RuleID,
                        Description=rule.Description,
                        StartLine=fragment.start_line + line_num - 1,
                        EndLine=fragment.start_line + line_num - 1,
                        StartColumn=match.start() + 1,
                        EndColumn=match.end(),
                        Match=match.group(0),
                        Secret=secret,
                        File=fragment.file_path,
                        Tags=rule.Tags
                    )
                    
                    # Calculate entropy
                    if rule.Entropy > 0:
                        entropy = finding.calculate_entropy()
                        if entropy < rule.Entropy:
                            continue
                    
                    # Check allowlists
                    allowed = False
                    
                    # Check global allowlist
                    if self.config.allowlist:
                        if self.config.allowlist.path_allowed(finding.File):
                            continue
                        
                        if self.config.allowlist.regex_allowed(finding.Secret):
                            continue
                    
                    # Check rule allowlists
                    for allowlist in rule.Allowlists:
                        commit_allowed = finding.Commit and allowlist.commit_allowed(finding.Commit)
                        path_allowed = allowlist.path_allowed(finding.File)
                        regex_allowed = allowlist.regex_allowed(finding.Secret)
                        
                        # Check if allowed based on match condition
                        if allowlist.MatchCondition == "AND":
                            allowlist_checks = []
                            
                            if allowlist.Commits:
                                allowlist_checks.append(commit_allowed)
                            
                            if allowlist.Paths:
                                allowlist_checks.append(path_allowed)
                            
                            if allowlist.Regexes:
                                allowlist_checks.append(regex_allowed)
                            
                            # Check if all conditions are true
                            allowed = all(allowlist_checks)
                        else:
                            allowed = commit_allowed or path_allowed or regex_allowed
                        
                        if allowed:
                            break
                    
                    if allowed:
                        continue
                    
                    findings.append(finding)
        
        return findings
    
    def scan_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan content for secrets.
        
        Args:
            content: Content to scan
            file_path: Path to the file
            
        Returns:
            List of findings
        """
        # Create a fragment from the content
        from detect.fragment import Fragment
        fragment = Fragment(
            raw=content,
            file_path=file_path,
            start_line=1
        )
        
        # Use the detect method to find secrets
        findings = self.detect(fragment)
        
        # Return findings
        return [finding.to_dict() for finding in findings]
    
    def _scan_line(self, line: str, line_num: int, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a line for secrets.
        
        Args:
            line: Line to scan
            line_num: Line number
            file_path: Path to the file
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check each rule
        for rule_id, rule in self.compiled_rules.items():
            # Skip if line doesn't contain any keywords
            if rule["keywords"] and not self._contains_keywords(line, rule["keywords"]):
                continue
            
            # Check for matches
            matches = self._find_matches(line, rule["pattern"])
            
            # Process matches
            for match in matches:
                # Get match details
                match_str = match.group(0)
                start_pos = match.start()
                end_pos = match.end()
                
                # Get secret
                secret = match_str
                if rule["secret_group"] > 0 and rule["secret_group"] <= len(match.groups()):
                    secret = match.group(rule["secret_group"])
                
                # Create finding
                finding = {
                    "RuleID": rule_id,
                    "Description": rule["description"],
                    "StartLine": line_num,
                    "EndLine": line_num,
                    "StartColumn": start_pos + 1,
                    "EndColumn": end_pos,
                    "Match": match_str,
                    "Secret": secret,
                    "File": file_path,
                    "SymlinkFile": "",
                    "Commit": "",
                    "Link": "",
                    "Entropy": 0.0,
                    "Author": "",
                    "Email": "",
                    "Date": "",
                    "Message": "",
                    "Tags": rule["tags"],
                    "Fingerprint": ""
                }
                
                # Calculate entropy if needed
                if rule["entropy"] > 0:
                    finding["Entropy"] = self._calculate_entropy(secret)
                    
                    # Skip if entropy is too low
                    if finding["Entropy"] < rule["entropy"]:
                        continue
                
                findings.append(finding)
        
        return findings
    
    def _contains_keywords(self, line: str, keywords: List[str]) -> bool:
        """
        Check if a line contains any keywords.
        
        Args:
            line: Line to check
            keywords: List of keywords to check for
            
        Returns:
            True if the line contains any keywords, False otherwise
        """
        line_lower = line.lower()
        
        for keyword in keywords:
            if keyword in line_lower:
                return True
        
        return False
    
    def _find_matches(self, line: str, pattern: Pattern) -> List[Match]:
        """
        Find all matches in a line.
        
        Args:
            line: Line to search
            pattern: Regex pattern to search for
            
        Returns:
            List of matches
        """
        matches = []
        
        # Find all matches
        for match in pattern.finditer(line):
            matches.append(match)
        
        return matches
    
    def _is_allowlisted(self, line: str) -> bool:
        """
        Check if a line is allowlisted.
        
        Args:
            line: Line to check
            
        Returns:
            True if the line is allowlisted, False otherwise
        """
        # Check if allowlist is configured
        if not self.config.allowlist:
            return False
            
        # Check if line contains allowlist markers
        if hasattr(self.config.allowlist, 'Regexes') and self.config.allowlist.Regexes:
            for marker in self.config.allowlist.Regexes:
                if marker.search(line):
                    return True
        
        return False
    
    def _calculate_entropy(self, s: str) -> float:
        """
        Calculate the entropy of a string.
        
        Args:
            s: String to calculate entropy for
            
        Returns:
            Entropy value
        """
        import math
        
        # Skip empty strings
        if not s:
            return 0.0
        
        # Count character frequencies
        char_count = {}
        for c in s:
            if c in char_count:
                char_count[c] += 1
            else:
                char_count[c] = 1
        
        # Calculate entropy
        entropy = 0.0
        for count in char_count.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        
        return entropy
        
    def add_finding(self, finding: Finding) -> None:
        """
        Add a finding to the detector.
        
        Args:
            finding: Finding to add
        """
        # Set description from rule if not already set
        if not finding.Description or finding.Description == "Generic API Key":
            for rule in self.config.rules:
                if rule.RuleID == finding.RuleID:
                    finding.Description = rule.Description
                    if self.config.verbose:
                        print(f"Set description from rule: {finding.RuleID} -> {finding.Description}")
                    break
                    
        # Generate fingerprint if not already set
        if not finding.Fingerprint:
            global_fingerprint = f"{finding.File}:{finding.RuleID}:{finding.StartLine}"
            if finding.Commit:
                finding.Fingerprint = f"{finding.Commit}:{finding.File}:{finding.RuleID}:{finding.StartLine}"
            else:
                finding.Fingerprint = global_fingerprint
        
        # Add finding
        with self.finding_mutex:
            self.findings.append(finding)
            if self.config.verbose:
                self._print_finding(finding)
    
    def get_findings(self) -> List[Finding]:
        """
        Get all findings.
        
        Returns:
            List of findings
        """
        return self.findings
        
    def _print_finding(self, finding: Finding) -> None:
        """
        Print a finding to the console.
        
        Args:
            finding: Finding to print
        """
        print(f"[{finding.RuleID}] {finding.Description}")
        print(f"  File: {finding.File}")
        print(f"  Line: {finding.StartLine}")
        print(f"  Secret: {finding.Secret}")
        print()
