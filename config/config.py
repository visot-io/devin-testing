"""
Configuration module for Gitleaks Python implementation.

This module handles loading and parsing configuration.
"""

import os
import re
import sys
import tomli
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern

# Try to import regex module for better regex support
try:
    import regex as regex_module
    USE_REGEX_MODULE = True
except ImportError:
    regex_module = None
    USE_REGEX_MODULE = False

from config.rule import Rule
from config.allowlist import Allowlist, MatchCondition


# Default configuration as a string
DEFAULT_CONFIG = """
# This is the default gitleaks configuration file.
# Rules and allowlists are defined within this file.
# Rules instruct gitleaks on what should be considered a secret.
# Allowlists instruct gitleaks on what is allowed, i.e. not a secret.

title = "gitleaks config"

[allowlist]
description = "global allow lists"
regexes = [
    '''(?i)^true|false|null$''',
    '''^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|[*]+|[.]+)$''',
    '''^[$](?:\\d+|{\\d+})$''',
    '''^[$](?:[A-Z_]+|[a-z_]+)$''',
    '''^[$]{(?:[A-Z_]+|[a-z_]+)}$''',
    '''^[{][{][ \t]*[\\w ().|]+[ \t]*}}$''',
    '''^[$][{][{][ \t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w "'&./=|]*)[ \t]*}}$''',
    '''^%(?:[A-Z_]+|[a-z_]+)%$''',
    '''^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$''',
    '''^[{]\\d{0,2}}$''',
    '''^@(?:[A-Z_]+|[a-z_]+)@$''',
    '''^/Users/(?i)[a-z0-9]+/[\\w .-/]+$''',
    '''^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$''',
]
paths = [
    '''gitleaks\\.toml''',
    '''(?i)\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$''',
    '''(?i)\\.(?:eot|[ot]tf|woff2?)$''',
    '''(?i)\\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf|zip)$''',
    '''go\\.(?:mod|sum|work(?:\\.sum)?)$''',
    '''(?:^|/)vendor/modules\\.txt$''',
    '''(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$''',
    '''(?:^|/)gradlew(?:\\.bat)?$''',
    '''(?:^|/)gradle\\.lockfile$''',
    '''(?:^|/)mvnw(?:\\.cmd)?$''',
    '''(?:^|/)\\.mvn/wrapper/MavenWrapperDownloader\\.java$''',
    '''(?:^|/)node_modules(?:/.*)?$''',
    '''(?:^|/)(?:deno\\.lock|npm-shrinkwrap\\.json|package-lock\\.json|pnpm-lock\\.yaml|yarn\\.lock)$''',
    '''(?:^|/)bower_components(?:/.*)?$''',
    '''(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\\.min)?\\.js(?:\\.map)?$''',
    '''(?:^|/)javascript\\.json$''',
    '''(?:^|/)(?:Pipfile|poetry)\\.lock$''',
]
stopwords = [
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
]

[[rules]]
id = "generic-api-key"
description = "Generic API Key"
regex = '''(?i)(?:api|access|auth|client|consumer|pass|secret|token|key|pwd|authorization|bearer)(?:_|-|:|[ ]|=)+[a-z0-9_\\-]{16,}'''
secretGroup = 0
entropy = 3.5
keywords = [
    "api",
    "token",
    "key",
    "secret",
    "client",
    "auth",
    "password",
    "bearer",
]
"""


@dataclass
class Config:
    """
    Config represents the configuration for Gitleaks.
    
    This class mirrors the Config struct in the original Gitleaks implementation.
    """
    
    # Rules for detecting secrets
    rules: List[Rule] = field(default_factory=list)
    
    # Global allowlist
    allowlist: Optional[Allowlist] = None
    
    # Description of the configuration
    description: str = ""
    
    # Path to the configuration file
    path: str = ""
    
    # Verbose output
    verbose: bool = False


def load_config(config_path: Optional[str] = None, source_path: str = ".") -> Config:
    """
    Load configuration from a file or use defaults.
    
    Args:
        config_path: Path to configuration file
        source_path: Path to source directory
        
    Returns:
        Loaded configuration
    """
    # Order of precedence:
    # 1. config_path
    # 2. GITLEAKS_CONFIG environment variable
    # 3. source_path/.gitleaks.toml
    # 4. Default config
    
    config_content = None
    config_file_path = None
    
    # Check config_path
    if config_path and os.path.isfile(config_path):
        config_file_path = config_path
    
    # Check environment variable
    if not config_file_path and "GITLEAKS_CONFIG" in os.environ:
        env_path = os.environ["GITLEAKS_CONFIG"]
        if os.path.isfile(env_path):
            config_file_path = env_path
    
    # Check source_path/.gitleaks.toml
    if not config_file_path:
        source_config = os.path.join(source_path, ".gitleaks.toml")
        if os.path.isfile(source_config):
            config_file_path = source_config
    
    # Load config from file or use default
    if config_file_path:
        try:
            with open(config_file_path, "rb") as f:
                config_content = tomli.load(f)
        except Exception as e:
            print(f"Error loading config from {config_file_path}: {e}")
            print("Using default config")
            config_content = tomli.loads(DEFAULT_CONFIG)
    else:
        config_content = tomli.loads(DEFAULT_CONFIG)
    
    # Create config
    config = Config()
    config.path = config_file_path or "default"
    
    # Parse description
    if "description" in config_content:
        config.description = config_content["description"]
    
    # Parse allowlist
    if "allowlist" in config_content:
        allowlist_data = config_content["allowlist"]
        allowlist = Allowlist()
        
        # Parse regexes
        if "regexes" in allowlist_data:
            for regex_str in allowlist_data["regexes"]:
                try:
                    # Fix global flags in regex
                    if '(?i)' in regex_str and not regex_str.startswith('(?i)'):
                        # Move global flags to the start
                        regex_str = re.sub(r'\(\?i\)', '', regex_str)
                        regex_str = f'(?i){regex_str}'
                    allowlist.Regexes.append(re.compile(regex_str))
                except Exception as e:
                    print(f"Error compiling regex {regex_str}: {e}")
        
        # Parse paths
        if "paths" in allowlist_data:
            for path_str in allowlist_data["paths"]:
                try:
                    allowlist.Paths.append(re.compile(path_str))
                except Exception as e:
                    print(f"Error compiling path regex {path_str}: {e}")
        
        # Parse commits
        if "commits" in allowlist_data:
            allowlist.Commits = allowlist_data["commits"]
        
        # Parse stopwords
        if "stopwords" in allowlist_data:
            allowlist.StopWords = allowlist_data["stopwords"]
        
        # Parse match condition
        if "match_condition" in allowlist_data:
            match_condition = allowlist_data["match_condition"].upper()
            if match_condition == "AND":
                allowlist.MatchCondition = MatchCondition.AND
        
        config.allowlist = allowlist
    
    # Parse rules
    if "rules" in config_content:
        for rule_data in config_content["rules"]:
            # Skip if no id or regex
            if "id" not in rule_data or "regex" not in rule_data:
                continue
            
            try:
                # Compile regex
                regex_pattern = None
                try:
                    # Try standard re module first
                    try:
                        regex_pattern = re.compile(rule_data["regex"])
                    except re.error as e:
                        print(f"Error compiling regex for rule {rule_data['id']}: {e}")
                        
                        # Try with a simplified pattern
                        simplified_pattern = rule_data["regex"]
                        # Fix \z escape sequence
                        simplified_pattern = simplified_pattern.replace("\\z", "\\b")
                        # Fix global flags not at the start
                        if '(?i)' in simplified_pattern and not simplified_pattern.startswith('(?i)'):
                            simplified_pattern = re.sub(r'\(\?i\)', '', simplified_pattern)
                            simplified_pattern = f'(?i){simplified_pattern}'
                        try:
                            regex_pattern = re.compile(simplified_pattern)
                            print(f"Successfully compiled simplified pattern for rule {rule_data['id']}")
                        except re.error:
                            # If we have the regex module available, try that
                            if 'regex_module' in globals() and regex_module is not None:
                                try:
                                    regex_pattern = regex_module.compile(rule_data["regex"])
                                    print(f"Successfully compiled pattern with regex module for rule {rule_data['id']}")
                                except Exception as e3:
                                    print(f"Error compiling with regex module: {e3}")
                                    continue
                            else:
                                print(f"Could not compile regex for rule {rule_data['id']}")
                                continue
                except Exception as e:
                    print(f"Error compiling regex for rule {rule_data['id']}: {e}")
                    continue
                
                if regex_pattern is None:
                    print(f"Skipping rule {rule_data['id']} due to regex compilation failure")
                    continue
                
                # Create rule with compiled regex
                rule = Rule(
                    RuleID=rule_data["id"],
                    Description=rule_data.get("description", "Generic API Key" if rule_data["id"] == "generic-api-key" else ""),
                    Regex=regex_pattern,
                    SecretGroup=rule_data.get("secretGroup", 0),
                    Entropy=rule_data.get("entropy", 0.0)
                )
                
                # Parse path
                if "path" in rule_data:
                    try:
                        rule.Path = re.compile(rule_data["path"])
                    except Exception as e:
                        print(f"Error compiling path regex for rule {rule.RuleID}: {e}")
                
                # Parse tags
                if "tags" in rule_data:
                    rule.Tags = rule_data["tags"]
                
                # Parse keywords
                if "keywords" in rule_data:
                    rule.Keywords = rule_data["keywords"]
                
                # Parse allowlists
                if "allowlist" in rule_data or "allowlists" in rule_data:
                    allowlists_data = rule_data.get("allowlists", [])
                    if "allowlist" in rule_data:
                        allowlists_data.append(rule_data["allowlist"])
                    
                    for allowlist_data in allowlists_data:
                        allowlist = Allowlist()
                        
                        # Parse regexes
                        if "regexes" in allowlist_data:
                            for regex_str in allowlist_data["regexes"]:
                                try:
                                    allowlist.Regexes.append(re.compile(regex_str))
                                except Exception as e:
                                    print(f"Error compiling regex for rule {rule.RuleID}: {e}")
                        
                        # Parse paths
                        if "paths" in allowlist_data:
                            for path_str in allowlist_data["paths"]:
                                try:
                                    allowlist.Paths.append(re.compile(path_str))
                                except Exception as e:
                                    print(f"Error compiling path regex for rule {rule.RuleID}: {e}")
                        
                        # Parse commits
                        if "commits" in allowlist_data:
                            allowlist.Commits = allowlist_data["commits"]
                        
                        # Parse stopwords
                        if "stopwords" in allowlist_data:
                            allowlist.StopWords = allowlist_data["stopwords"]
                        
                        # Parse match condition
                        if "match_condition" in allowlist_data:
                            match_condition = allowlist_data["match_condition"].upper()
                            if match_condition == "AND":
                                allowlist.MatchCondition = MatchCondition.AND
                        
                        rule.Allowlists.append(allowlist)
                
                # Validate rule
                error = rule.validate()
                if error:
                    print(f"Warning: {error}")
                    continue
                
                config.rules.append(rule)
            except Exception as e:
                print(f"Error parsing rule {rule_data.get('id', 'unknown')}: {e}")
    
    return config
