"""
Rule module for Gitleaks Python implementation.

This module defines the Rule class, which represents a rule for detecting secrets.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern

from config.allowlist import Allowlist


@dataclass
class Rule:
    """
    Rule represents a rule for detecting secrets.
    
    This class mirrors the Rule struct in the original Gitleaks implementation.
    """
    
    # Rule identification
    RuleID: str
    Description: str
    
    # Regex pattern for detecting secrets
    Regex: Pattern
    
    # Group in the regex that contains the secret
    SecretGroup: int = 0
    
    # Entropy threshold for the secret
    Entropy: float = 0.0
    
    # Path pattern to filter files
    Path: Optional[Pattern] = None
    
    # Tags for categorizing the rule
    Tags: List[str] = field(default_factory=list)
    
    # Keywords for pre-regex filtering
    Keywords: List[str] = field(default_factory=list)
    
    # Allowlists for this rule
    Allowlists: List[Allowlist] = field(default_factory=list)
    
    # Whether the rule is enabled
    Enabled: bool = True
    
    def validate(self) -> Optional[str]:
        """
        Validate the rule configuration.
        
        Returns:
            Error message if validation fails, None otherwise
        """
        # Ensure RuleID is present
        if not self.RuleID or self.RuleID.strip() == "":
            context = ""
            if self.Regex:
                context = f", regex: {self.Regex.pattern}"
            elif self.Path:
                context = f", path: {self.Path.pattern}"
            elif self.Description:
                context = f", description: {self.Description}"
            return f"rule |id| is missing or empty{context}"
        
        # Ensure the rule actually matches something
        if not self.Regex and not self.Path:
            return f"{self.RuleID}: both |regex| and |path| are empty, this rule will have no effect"
        
        # Ensure SecretGroup is valid
        if self.Regex and self.SecretGroup > 0:
            # Count groups in regex
            group_count = self.Regex.groups
            if self.SecretGroup > group_count:
                return f"{self.RuleID}: invalid regex secret group {self.SecretGroup}, max regex secret group {group_count}"
        
        return None
