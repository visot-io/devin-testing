from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Body
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
from pydantic import BaseModel
import tomllib
from pathlib import Path
import tempfile
import shutil
import re
import json

# Import required modules
from app.models.rules import Rule
from app.models.findings import Finding
from app.core.scanner import Scanner
from app.core.git import GitScanner
from app.utils.config import get_github_config

app = FastAPI(title="Gitleaks API", description="API for detecting secrets in code")

# Add server startup for direct execution
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Disable CORS. Do not remove this for full-stack development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Load GitHub configuration
github_config = get_github_config()

def load_rules(config_path: Optional[str] = None) -> List[Rule]:
    """Load rules from a TOML configuration file."""
    try:
        if config_path:
            with open(config_path, "rb") as f:
                config = tomllib.load(f)
        else:
            # Load default rules
            default_config_path = Path(__file__).parent / "config" / "default_rules.toml"
            if not default_config_path.exists():
                raise FileNotFoundError(f"Default rules file not found at {default_config_path}")
            
            print(f"\nLoading rules from: {default_config_path}")
            with open(default_config_path, "rb") as f:
                config = tomllib.load(f)
            print("Successfully loaded TOML config")
            
        if not config:
            raise ValueError("Empty configuration")
        if "rules" not in config:
            raise ValueError("No rules section found in configuration")
        if not config["rules"]:
            raise ValueError("Rules section is empty")
            
        print(f"\nFound {len(config['rules'])} rules in config")
        rules = []
        for rule_data in config["rules"]:
            try:
                print(f"\nProcessing rule: {rule_data.get('id', 'unknown')}")
                print(f"Rule data: {rule_data}")
                print(f"\nProcessing rule data: {rule_data}")
                try:
                    # Extract and validate required fields
                    rule_dict = {
                        "id": rule_data["id"],
                        "description": rule_data["description"],
                        "regex": rule_data["regex"],
                        "secretGroup": rule_data.get("secretGroup", 1),
                        "entropy": rule_data.get("entropy"),
                        "path": rule_data.get("path"),
                        "keywords": rule_data.get("keywords", []),
                        "allowlist": rule_data.get("allowlist")
                    }
                    print(f"Validated rule data: {rule_dict}")
                    
                    # Create rule instance
                    rule = Rule(**rule_dict)
                    print(f"Created rule: {rule}")
                    rules.append(rule)
                except KeyError as e:
                    print(f"Missing required field: {e}")
                    raise ValueError(f"Missing required field in rule: {e}")
                except Exception as e:
                    print(f"Error creating rule: {e}")
                    raise ValueError(f"Error creating rule: {e}")
            except Exception as e:
                print(f"Error creating rule: {str(e)}")
                raise
                
        print(f"\nSuccessfully loaded {len(rules)} rules")
        return rules

        if not config:
            raise ValueError("Empty configuration")
        if "rules" not in config:
            raise ValueError("No rules section found in configuration")
        if not config["rules"]:
            raise ValueError("Rules section is empty")
            
        # Get global allowlist if present
        global_allowlist = config.get("allowlist")
        
        # Create rules with detailed error handling
        rules = []
        for rule_data in config["rules"]:
            try:
                print(f"\nProcessing rule: {rule_data.get('id', 'unknown')}")
                print(f"Raw rule data: {rule_data}")
                
                # Get raw data first for debugging
                print(f"\nRaw rule data for {rule_data.get('id')}:")
                for key, value in rule_data.items():
                    print(f"{key}: {value!r} (type: {type(value)})")
                
                # Convert TOML data to proper format
                clean_data = {
                    "id": str(rule_data["id"]),
                    "description": str(rule_data["description"]),
                    "regex": rule_data["regex"],  # Keep original TOML string
                    "secretGroup": int(rule_data.get("secretGroup", 1)),
                    "entropy": float(rule_data.get("entropy", 0.0)) if "entropy" in rule_data else None,
                    "path": str(rule_data.get("path", "")) if "path" in rule_data else None,
                    "keywords": list(rule_data.get("keywords", [])),
                    "allowlist": global_allowlist if global_allowlist else None
                }
                print(f"Processed rule data: {clean_data}")  # Debug print
                print(f"Cleaned rule data: {clean_data}")
                
                # Create rule
                rule = Rule(**clean_data)
                print(f"Successfully created rule: {rule}")
                rules.append(rule)
            except Exception as e:
                print(f"Error creating rule {rule_data.get('id')}: {str(e)}")
                print(f"Full error: {type(e).__name__}: {str(e)}")
                raise
                
        return rules
        
        # Create Rule instances
        rules = []
        for rule_data in config["rules"]:
            try:
                rule = Rule.from_toml(rule_data, global_allowlist)
                rules.append(rule)
            except Exception as e:
                print(f"Error creating rule {rule_data.get('id')}: {str(e)}")
                raise

        return rules

        print(f"Found {len(config['rules'])} rules")
        rules = []
        global_allowlist = config.get("allowlist")
        
        for rule_data in config["rules"]:
            try:
                print(f"\nProcessing rule: {rule_data}")
                # Create rule using from_toml classmethod
                rule = Rule.from_toml(rule_data, global_allowlist)
                print(f"Successfully created rule: {rule}")
                rules.append(rule)
            except Exception as e:
                print(f"Error creating rule from data {rule_data}: {str(e)}")
                raise

        return rules
    except Exception as e:
        print(f"Error loading rules: {str(e)}")
        raise

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

class GitScanRequest(BaseModel):
    repository_url: Optional[str] = None
    baseline_path: Optional[str] = None
    config_path: Optional[str] = None
    log_opts: Optional[str] = None
    max_target_megabytes: Optional[int] = None
    redact: Optional[int] = 100

from fastapi import Body
@app.post("/api/v1/scan/git", response_class=PlainTextResponse)
async def scan_git_repo(
    request: Optional[GitScanRequest] = Body(default=None)
):
    """
    Scan a git repository for secrets. If no request body is provided,
    uses repository and token from config.ini.
    """
    try:
        # Load rules
        rules = load_rules(request.config_path if request else None)
        
        # Create scanner
        git_scanner = GitScanner(rules)
        
        # If no request or repository_url, use config.ini
        if not request or not request.repository_url:
            github_config = get_github_config()
            if not github_config['token']:
                raise ValueError("GitHub token not found in config.ini")
            if not github_config['repo']:
                raise ValueError("Repository not specified in config.ini")
                
            repo = github_config['repo']
            token = github_config['token']
            repository_url = f"https://github.com/{repo}.git"
            log_opts = ""
            redact = 100
        else:
            repository_url = request.repository_url
            token = None
            log_opts = request.log_opts or ""
            redact = request.redact
            
        # Scan repository
        findings = list(git_scanner.scan_repository(repository_url, log_opts, token=token))
        
        # Apply baseline if provided
        if request and request.baseline_path:
            with open(request.baseline_path, "rb") as f:
                baseline = tomllib.load(f)
                baseline_fingerprints = {f["Fingerprint"] for f in baseline.get("findings", [])}
                findings = [f for f in findings if f.Fingerprint not in baseline_fingerprints]
        
        # Apply redaction if requested
        if redact is not None:
            for finding in findings:
                if redact == 100:
                    finding.Secret = "**********"
                else:
                    length = len(finding.Secret)
                    redact_length = int(length * (redact / 100))
                    finding.Secret = finding.Secret[:length - redact_length] + "*" * redact_length
        
        # Format output to match gitleaks CLI exactly
        output = [
            "",  # Empty line before logo
            "    ○",
            "    │╲",
            "    │ ○",
            "    ○ ░",
            "    ░    gitleaks",
            "",  # Empty line after logo
            "",  # Extra empty line before findings
            ""   # Another empty line before findings
        ]
        
        if not findings:
            output.append("No leaks found")
        else:
            # Format findings to match gitleaks output exactly
            findings_json = []
            for finding in findings:
                findings_json.append({
                    "RuleID": finding.RuleID,
                    "Description": finding.Description,
                    "StartLine": finding.StartLine,
                    "EndLine": finding.EndLine,
                    "StartColumn": finding.StartColumn,
                    "EndColumn": finding.EndColumn,
                    "Match": finding.Match,
                    "Secret": finding.Secret,
                    "File": finding.File,
                    "SymlinkFile": finding.SymlinkFile,
                    "Commit": finding.Commit,
                    "Link": finding.Link,
                    "Entropy": finding.Entropy,
                    "Author": finding.Author,
                    "Email": finding.Email,
                    "Date": finding.Date,
                    "Message": finding.Message,
                    "Tags": finding.Tags,
                    "Fingerprint": finding.Fingerprint
                })
            output.append(json.dumps(findings_json, indent=1))
        
        return "\n".join(output)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class DirScanRequest(BaseModel):
    baseline_path: Optional[str] = None
    config_path: Optional[str] = None
    max_target_megabytes: Optional[int] = None
    redact: Optional[int] = 100

    @classmethod
    def parse_raw_request(cls, request_str: str) -> "DirScanRequest":
        """Parse request string into DirScanRequest object."""
        try:
            data = json.loads(request_str)
            return cls(**data)
        except Exception as e:
            print(f"Error parsing request: {str(e)}")
            raise ValueError(f"Invalid request format: {str(e)}")

@app.post("/api/v1/scan/dir", response_model=List[Finding])
async def scan_directory(
    files: List[UploadFile] = File(...),
    request: str = Form(...)
):
    """
    Scan uploaded files for secrets.
    """
    try:
        request_obj = DirScanRequest.parse_raw_request(request)
        
        # Load rules
        rules = load_rules(request_obj.config_path)
        
        # Create scanner
        scanner = Scanner(rules)
        
        findings = []
        
        # Create temporary directory for files
        with tempfile.TemporaryDirectory() as temp_dir:
            for file in files:
                file_path = Path(temp_dir) / file.filename
                
                # Check file size if limit is set
                if request_obj.max_target_megabytes:
                    if file.size > request_obj.max_target_megabytes * 1024 * 1024:
                        continue
                
                # Save file
                with open(file_path, "wb") as f:
                    shutil.copyfileobj(file.file, f)
                
                # Read and scan file
                with open(file_path, "r") as f:
                    content = f.read()
                    file_findings = scanner.scan_content(content, path=file.filename)
                    findings.extend(file_findings)
        
        # Apply baseline if provided
        if request_obj.baseline_path:
            with open(request_obj.baseline_path, "rb") as f:
                baseline = tomllib.load(f)
                baseline_fingerprints = {f["fingerprint"] for f in baseline.get("findings", [])}
                findings = [f for f in findings if f.fingerprint not in baseline_fingerprints]
        
        # Apply redaction if requested
        if request_obj.redact is not None:
            for finding in findings:
                if request_obj.redact == 100:
                    finding.secret = "**********"
                else:
                    # Partial redaction
                    length = len(finding.secret)
                    redact_length = int(length * (request_obj.redact / 100))
                    finding.secret = finding.secret[:length - redact_length] + "*" * redact_length
        
        return findings
    except Exception as e:
        print(f"Error in scan_directory: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
        # Load rules
        rules = load_rules(request.config_path)
        
        # Create scanner
        scanner = Scanner(rules)
        
        findings = []
        
        # Create temporary directory for files
        with tempfile.TemporaryDirectory() as temp_dir:
            for file in files:
                file_path = Path(temp_dir) / file.filename
                
                # Check file size if limit is set
                if request.max_target_megabytes:
                    if file.size > request.max_target_megabytes * 1024 * 1024:
                        continue
                
                # Save file
                with open(file_path, "wb") as f:
                    shutil.copyfileobj(file.file, f)
                
                # Read and scan file
                with open(file_path, "r") as f:
                    content = f.read()
                    file_findings = scanner.scan_content(content, path=file.filename)
                    findings.extend(file_findings)
        
        # Apply baseline if provided
        if request.baseline_path:
            with open(request.baseline_path, "rb") as f:
                baseline = tomllib.load(f)
                baseline_fingerprints = {f["fingerprint"] for f in baseline.get("findings", [])}
                findings = [f for f in findings if f.fingerprint not in baseline_fingerprints]
        
        # Apply redaction if requested
        if request.redact is not None:
            for finding in findings:
                if request.redact == 100:
                    finding.secret = "**********"
                else:
                    # Partial redaction
                    length = len(finding.secret)
                    redact_length = int(length * (request.redact / 100))
                    finding.secret = finding.secret[:length - redact_length] + "*" * redact_length
        
        return findings
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

from pydantic import BaseModel

@app.get("/api/v1/scan/config", response_class=PlainTextResponse)
async def scan_configured_repo():
    """
    Scan the GitHub repository configured in config.ini for secrets.
    """
    try:
        # Load configuration
        github_config = get_github_config()
        if not github_config['token']:
            raise ValueError("GitHub token not found in config.ini")
        if not github_config['repo']:
            raise ValueError("Repository not specified in config.ini")
            
        # Load rules
        rules = load_rules()
        
        # Create scanner
        git_scanner = GitScanner(rules)
        
        try:
            # Construct repository URL
            repo = github_config['repo']  # Should already be in format owner/repo
            token = github_config['token']
            
            # Format URL properly for git clone
            print(f"\nRepository: {repo}")
            print(f"Token available: {'yes' if token else 'no'}")
            # Pass token separately to scan_repository
            print(f"Scanning repository: {repo}")
            
            # Scan repository with token
            findings = list(git_scanner.scan_repository(f"https://github.com/{repo}.git", token=token))
            
            # Apply redaction
            for finding in findings:
                finding.secret = "**********"
            
            # Format output to match gitleaks CLI exactly
            output = [
                "",  # Empty line before logo
                "    ○",
                "    │╲",
                "    │ ○",
                "    ○ ░",
                "    ░    gitleaks",
                "",  # Empty line after logo
                "",  # Extra empty line before findings
                ""   # Another empty line before findings
            ]
            
            if not findings:
                output.append("No leaks found")
            else:
                for finding in findings:
                    output.append(str(finding))
                    output.append("")  # Empty line between findings
            
            # Return plain text response
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse("\n".join(output))
            
        except Exception as e:
            # Format error output to match gitleaks CLI
            error_output = [
                "",
                "    ○",
                "    │╲",
                "    │ ○",
                "    ○ ░",
                "    ░    gitleaks",
                "",
                f"Error: {str(e)}",
                "",
                "Need help? Join our Discord https://discord.gg/Z8Tpt5hYQk or visit our website https://gitleaks.io"
            ]
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse("\n".join(error_output))
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class TextScanRequest(BaseModel):
    content: str
    config_path: Optional[str] = None
    redact: Optional[int] = 100
    metadata: Optional[dict] = None  # For commit, author, email, date info

@app.post("/api/v1/scan/text", response_class=PlainTextResponse)
async def scan_text(
    request: TextScanRequest
):
    """
    Scan text content for secrets.
    """
    try:
        # Load rules
        rules = load_rules(request.config_path)
        
        # Create scanner
        scanner = Scanner(rules)
        
        # Prepare metadata for scanner
        metadata = None
        if request.metadata:
            metadata = {
                'commit': request.metadata.get('commit'),
                'author': request.metadata.get('author'),
                'email': request.metadata.get('email'),
                'date': request.metadata.get('date'),
                'file': request.metadata.get('file', 'text'),
                'line': request.metadata.get('line', 1)
            }
        
        # Scan content with metadata
        findings = scanner.scan_content(
            request.content,
            path=metadata.get('file') if metadata else 'text',
            commit_info=metadata
        )
        
        # Format output to match gitleaks CLI exactly
        output = [
            "",  # Empty line before logo
            "    ○",
            "    │╲",
            "    │ ○",
            "    ○ ░",
            "    ░    gitleaks",
            "",  # Empty line after logo
            "",  # Extra empty line before findings
            ""   # Another empty line before findings
        ]
        
        if not findings:
            output.append("No leaks found")
        else:
            for finding in findings:
                # Only apply redaction if explicitly requested
                if request.redact and request.redact > 0:
                    if request.redact >= 100:
                        finding.secret = "**********"
                    else:
                        length = len(finding.secret)
                        redact_length = int(length * (request.redact / 100))
                        finding.secret = finding.secret[:length - redact_length] + "*" * redact_length
                output.append(str(finding))
                output.append("")  # Empty line between findings
        
        return "\n".join(output)
        
    except Exception as e:
        # Format error output to match gitleaks CLI
        error_output = [
            "",
            "    ○",
            "    │╲",
            "    │ ○",
            "    ○ ░",
            "    ░    gitleaks",
            "",
            f"Error: failed to scan text - {str(e)}",
            ""
        ]
        return "\n".join(error_output)
