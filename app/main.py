# Import all required modules
import json
import os
import tempfile
import shutil
import uuid
import re
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import logging
import base64
from datetime import datetime

# Import FastAPI and related modules
try:
    from fastapi import (
        FastAPI,
        File,
        UploadFile,
        Form,
        HTTPException,
        Depends,
        Query,
        Body,
        Request,
    )
    from fastapi.responses import JSONResponse, PlainTextResponse
    from fastapi.middleware.cors import CORSMiddleware
except ImportError:
    raise ImportError("FastAPI is required. Install it with: pip install fastapi")

# Import Pydantic
try:
    import pydantic
    from pydantic import BaseModel, Field
except ImportError:
    raise ImportError("Pydantic is required. Install it with: pip install pydantic")

# Import Uvicorn
try:
    import uvicorn
except ImportError:
    raise ImportError("Uvicorn is required. Install it with: pip install uvicorn")

# Import our gitleaks_py module
from gitleaks_py.scanner import Scanner
from gitleaks_py.reporter import Reporter
from gitleaks_py.config import Config

# Create FastAPI app
app = FastAPI()


# Configure FastAPI to use custom JSON encoder for pretty printing
class PrettyJSONResponse(JSONResponse):
    media_type = "application/json; charset=utf-8"

    def render(self, content) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            separators=(",", ": "),
        ).encode("utf-8")


# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Define models
class GitLeaksFinding(BaseModel):
    """
    Represents a finding in the gitleaks CLI format.
    This model exactly matches the Finding struct in the gitleaks codebase.
    """

    RuleID: str
    Description: str
    StartLine: int
    EndLine: int
    StartColumn: int
    EndColumn: int
    Match: str
    Secret: str
    File: str
    SymlinkFile: str = ""
    Commit: str = ""
    Link: Optional[str] = None
    Entropy: float
    Author: str = ""
    Email: str = ""
    Date: str = ""
    Message: str = ""
    Tags: List[str] = Field(default_factory=list)
    Fingerprint: str


class ScanResult(BaseModel):
    findings: List[Dict[str, Any]] = []
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    scan_duration: float = 0.0
    status: str = "success"
    error_message: Optional[str] = None


class ScanRequest(BaseModel):
    content: Optional[str] = None
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    path: Optional[str] = None
    scan_type: str = "content"  # content, repo, file
    cli_format: bool = False  # Toggle for CLI format


# Define conversion function
def convert_to_gitleaks_format(findings):
    """
    Convert API findings to gitleaks CLI format.

    This function transforms our internal API findings (with snake_case field names)
    to the gitleaks CLI format (with PascalCase field names) to ensure compatibility
    with tools that expect the original gitleaks output format.
    """
    gitleaks_findings = []

    for finding in findings:
        gitleaks_finding = {
            "RuleID": finding.get("rule_id", ""),
            "Description": finding.get("description", ""),
            "StartLine": int(finding.get("start_line", 0)),
            "EndLine": int(finding.get("end_line", 0)),
            "StartColumn": int(finding.get("start_column", 0)),
            "EndColumn": int(finding.get("end_column", 0)),
            "Match": finding.get("match", ""),
            "Secret": finding.get("secret", ""),
            "File": finding.get("file", ""),
            "SymlinkFile": finding.get("symlink_file", ""),
            "Commit": finding.get("commit", ""),
            "Entropy": float(finding.get("entropy", 0.0)),
            "Author": finding.get("author", ""),
            "Email": finding.get("email", ""),
            "Date": finding.get("date", ""),
            "Message": finding.get("message", ""),
            "Tags": finding.get("tags", []),
            "Fingerprint": finding.get("fingerprint", ""),
        }

        # Handle Link field with omitempty behavior
        if finding.get("link"):
            gitleaks_finding["Link"] = finding.get("link")

        gitleaks_findings.append(gitleaks_finding)

    return gitleaks_findings


# Load configuration
config = Config("config.ini")

# Create scanner instance with config
scanner = Scanner(config_path="config.ini")


# API endpoints
@app.get("/", response_class=PrettyJSONResponse)
async def root():
    return {"message": "Gitleaks API is running"}


@app.get("/health", response_class=PrettyJSONResponse)
async def health_check():
    return {"status": "healthy"}


@app.post("/scan/config", response_class=PrettyJSONResponse)
async def scan_config(
    cli_format: bool = Query(False, description="Return in gitleaks CLI format")
):
    """
    Scan the repository specified in the config file.
    No parameters required in the request.
    """
    try:
        # Get GitHub config
        github_config = config.get_github_config()

        if not github_config["repo"]:
            if cli_format:
                return []
            return ScanResult(
                status="error", error_message="No repository specified in config file"
            )

        # Scan repository
        result = scanner.scan_repo()

        if cli_format:
            return convert_to_gitleaks_format(result.get("findings", []))

        return ScanResult(
            findings=result.get("findings", []),
            scan_duration=result.get("scan_duration", 0.0),
            status=result.get("status", "success"),
            error_message=result.get("error_message"),
        )

    except Exception as e:
        logger.error(f"Error processing config scan request: {str(e)}")
        if cli_format:
            return []
        return ScanResult(status="error", error_message=str(e))


@app.post("/scan", response_class=PrettyJSONResponse)
async def scan(request: ScanRequest):
    try:
        if request.scan_type == "content" and request.content:
            # Ensure path is not None
            path = request.path if request.path else "temp.txt"
            result = scanner.scan_content(request.content, path)
        elif request.scan_type == "repo":
            # Use repo_url from request if provided, otherwise use from config
            result = scanner.scan_repo(request.repo_url, request.branch)
        elif request.scan_type == "file" and request.path:
            # Ensure path is not None before using it
            if request.path is not None:
                result = scanner.scan_file(request.path)
            else:
                if request.cli_format:
                    return []
                return ScanResult(
                    status="error", error_message="Path is required for file scan"
                )
        else:
            if request.cli_format:
                return []
            return ScanResult(
                status="error",
                error_message="Invalid scan request. Please provide required parameters.",
            )

        # Check if result is not None before accessing
        if result is not None and result.get("status") == "error":
            if request.cli_format:
                return []
            return ScanResult(
                status="error",
                error_message=result.get("error_message", "Unknown error"),
                findings=result.get("findings", []),
                scan_duration=result.get("scan_duration", 0.0),
            )

        if request.cli_format:
            return convert_to_gitleaks_format(result.get("findings", []))

        return ScanResult(
            findings=result.get("findings", []),
            scan_duration=result.get("scan_duration", 0.0),
        )

    except Exception as e:
        logger.error(f"Error processing scan request: {str(e)}")
        if request.cli_format:
            return []
        return ScanResult(status="error", error_message=str(e))


# Define file upload model
class FileUploadRequest(BaseModel):
    scan_type: str = "file"


@app.post("/upload", response_class=PrettyJSONResponse)
async def upload_file(file: UploadFile = File(...), cli_format: bool = Form(False)):
    try:
        temp_dir = Path(tempfile.mkdtemp())
        # Ensure filename is not None before using it with the / operator
        filename = file.filename if file.filename is not None else "uploaded_file"
        temp_file = temp_dir / filename

        try:
            contents = await file.read()
            with open(temp_file, "wb") as f:
                f.write(contents)

            result = scanner.scan_file(str(temp_file))

            if cli_format:
                return convert_to_gitleaks_format(result.get("findings", []))

            return ScanResult(
                findings=result.get("findings", []),
                scan_duration=result.get("scan_duration", 0.0),
                status=result.get("status", "success"),
                error_message=result.get("error_message"),
            )

        finally:
            shutil.rmtree(temp_dir)

    except Exception as e:
        logger.error(f"Error processing file upload: {str(e)}")
        if cli_format:
            return []
        return ScanResult(status="error", error_message=str(e))


@app.post("/scan/text", response_class=PrettyJSONResponse)
async def scan_text(request: Request, cli_format: bool = Query(False)):
    try:
        body = await request.body()
        text_content = body.decode("utf-8")

        if not text_content:
            if cli_format:
                return []
            return PrettyJSONResponse(
                content={"status": "error", "error_message": "No content provided"},
                status_code=400,
                headers={"Content-Type": "application/json; charset=utf-8"},
            )

        result = scanner.scan_content(text_content)

        if cli_format:
            return convert_to_gitleaks_format(result.get("findings", []))

        return ScanResult(
            findings=result.get("findings", []),
            scan_duration=result.get("scan_duration", 0.0),
            status=result.get("status", "success"),
            error_message=result.get("error_message"),
        )

    except Exception as e:
        logger.error(f"Error processing text scan: {str(e)}")
        if cli_format:
            return []
        return PrettyJSONResponse(
            content={"status": "error", "error_message": str(e)},
            status_code=500,
            headers={"Content-Type": "application/json; charset=utf-8"},
        )


@app.post("/scan/base64", response_class=PrettyJSONResponse)
async def scan_base64(request: Request, cli_format: bool = Query(False)):
    try:
        body = await request.body()
        encoded_content = body.decode("utf-8")

        if not encoded_content:
            if cli_format:
                return []
            return PrettyJSONResponse(
                content={"status": "error", "error_message": "No content provided"},
                status_code=400,
                headers={"Content-Type": "application/json; charset=utf-8"},
            )

        try:
            decoded_content = base64.b64decode(encoded_content).decode("utf-8")
        except Exception as e:
            if cli_format:
                return []
            return PrettyJSONResponse(
                content={
                    "status": "error",
                    "error_message": f"Invalid base64 encoding: {str(e)}",
                },
                status_code=400,
                headers={"Content-Type": "application/json; charset=utf-8"},
            )

        # Ensure path is a string
        result = scanner.scan_content(decoded_content, "base64_content.txt")

        if cli_format:
            return convert_to_gitleaks_format(result.get("findings", []))

        return ScanResult(
            findings=result.get("findings", []),
            scan_duration=result.get("scan_duration", 0.0),
            status=result.get("status", "success"),
            error_message=result.get("error_message"),
        )

    except Exception as e:
        logger.error(f"Error processing base64 scan: {str(e)}")
        if cli_format:
            return []
        return ScanResult(status="error", error_message=str(e))


@app.post("/scan/cli", response_class=PrettyJSONResponse)
async def scan_cli(request: ScanRequest):
    """
    Scan with gitleaks CLI format output.
    This endpoint always returns in gitleaks CLI format.
    """
    request.cli_format = True
    return await scan(request)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
