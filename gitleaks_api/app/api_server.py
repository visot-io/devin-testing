#!/usr/bin/env python3
"""
Gitleaks Python REST API Server.

This module provides a REST API for using Gitleaks Python
with automatic credential loading from config.ini.
"""

import os
import sys
import json
from typing import Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import API functions
from api import load_github_config, scan_repository, generate_report


# Define API models
class ScanRequest(BaseModel):
    """Request model for scan endpoint."""
    redact: bool = False
    verbose: bool = False
    output_format: str = "json"
    config_path: Optional[str] = None


class ScanResponse(BaseModel):
    """Response model for scan endpoint."""
    findings: List[Dict]
    count: int


# Create FastAPI app
app = FastAPI(
    title="Gitleaks Python API",
    description="REST API for Gitleaks Python",
    version="1.0.0"
)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Gitleaks Python API",
        "version": "1.0.0",
        "endpoints": [
            "/scan",
            "/scan/json",
            "/health"
        ]
    }


@app.post("/scan")
async def api_scan(request: ScanRequest = Body(...)):
    """
    Scan a repository for secrets using configuration from config.ini.
    
    Args:
        request: Scan request parameters
        
    Returns:
        JSON response with findings
    """
    try:
        # Check if config.ini exists in script directory or current directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if not (os.path.exists('config.ini') or os.path.exists(os.path.join(script_dir, 'config.ini'))):
            raise HTTPException(
                status_code=400,
                detail="config.ini not found. Please create a config.ini file with GitHub credentials."
            )
        
        # Use the config_path from the request if provided, otherwise check for gitleaks.toml
        config_path = request.config_path
        if not config_path:
            # Check for gitleaks.toml in current directory or script directory
            if os.path.exists('gitleaks.toml'):
                config_path = os.path.abspath('gitleaks.toml')
                if request.verbose:
                    print(f"Using gitleaks.toml from current directory: {config_path}")
            elif os.path.exists(os.path.join(script_dir, 'gitleaks.toml')):
                config_path = os.path.join(script_dir, 'gitleaks.toml')
                if request.verbose:
                    print(f"Using gitleaks.toml from script directory: {config_path}")
            # Fallback to gitleaks_official.toml
            elif os.path.exists('gitleaks_official.toml'):
                config_path = os.path.abspath('gitleaks_official.toml')
                if request.verbose:
                    print(f"Using gitleaks_official.toml from current directory: {config_path}")
            elif os.path.exists(os.path.join(script_dir, 'gitleaks_official.toml')):
                config_path = os.path.join(script_dir, 'gitleaks_official.toml')
                if request.verbose:
                    print(f"Using gitleaks_official.toml from script directory: {config_path}")
        
        # Set environment variable for configuration
        if config_path:
            os.environ["GITLEAKS_CONFIG"] = config_path
            if request.verbose:
                print(f"Set GITLEAKS_CONFIG environment variable to: {config_path}")
        
        # Scan repository
        findings, error = scan_repository(
            config_path=config_path,
            verbose=request.verbose
        )
        
        if error:
            raise HTTPException(
                status_code=500,
                detail=f"Error scanning repository: {error}"
            )
        
        # Generate report
        if request.redact:
            # Import here to avoid circular imports
            from report.finding import Finding
            
            # Convert findings to Finding objects and redact
            finding_objects = []
            for finding in findings:
                finding_obj = Finding(**finding)
                finding_obj.redact(100)
                finding_objects.append(finding_obj.to_dict())
            
            findings = finding_objects
        
        # Return response
        return ScanResponse(
            findings=findings,
            count=len(findings)
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error scanning repository: {str(e)}"
        )


@app.get("/scan/json")
async def api_scan_json(
    target_dir: str = Query(..., description="Directory or file to scan"),
    redact: bool = Query(False, description="Whether to redact secrets"),
    verbose: bool = Query(False, description="Whether to show verbose output"),
    config_path: Optional[str] = Query(None, description="Path to gitleaks.toml configuration file")
):
    """
    Scan a repository and return findings as JSON.
    
    Args:
        redact: Whether to redact secrets
        verbose: Whether to show verbose output
        config_path: Path to gitleaks.toml configuration file
        
    Returns:
        JSON response with findings
    """
    try:
        # Check if config.ini exists in script directory or current directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if not (os.path.exists('config.ini') or os.path.exists(os.path.join(script_dir, 'config.ini'))):
            raise HTTPException(
                status_code=400,
                detail="config.ini not found. Please create a config.ini file with GitHub credentials."
            )
        
        # Use the provided config_path if available, otherwise check for gitleaks.toml
        if not config_path:
            # Check for gitleaks.toml in current directory or script directory
            if os.path.exists('gitleaks.toml'):
                config_path = os.path.abspath('gitleaks.toml')
                if verbose:
                    print(f"Using gitleaks.toml from current directory: {config_path}")
            elif os.path.exists(os.path.join(script_dir, 'gitleaks.toml')):
                config_path = os.path.join(script_dir, 'gitleaks.toml')
                if verbose:
                    print(f"Using gitleaks.toml from script directory: {config_path}")
            # Fallback to gitleaks_official.toml
            elif os.path.exists('gitleaks_official.toml'):
                config_path = os.path.abspath('gitleaks_official.toml')
                if verbose:
                    print(f"Using gitleaks_official.toml from current directory: {config_path}")
            elif os.path.exists(os.path.join(script_dir, 'gitleaks_official.toml')):
                config_path = os.path.join(script_dir, 'gitleaks_official.toml')
                if verbose:
                    print(f"Using gitleaks_official.toml from script directory: {config_path}")
        
        # Set environment variable for configuration
        if config_path:
            os.environ["GITLEAKS_CONFIG"] = config_path
            if verbose:
                print(f"Set GITLEAKS_CONFIG environment variable to: {config_path}")
        
        # Scan repository
        findings, error = scan_repository(
            target_dir=target_dir,
            config_path=config_path,
            verbose=verbose
        )
        
        if error:
            raise HTTPException(
                status_code=500,
                detail=f"Error scanning repository: {error}"
            )
        
        # Update descriptions from config file
        if config_path and os.path.exists(config_path):
            from config.config import load_config
            config = load_config(config_path)
            rule_descriptions = {}
            for rule in config.rules:
                rule_descriptions[rule.RuleID] = rule.Description
            
            # Update findings with correct descriptions
            for finding in findings:
                if finding["RuleID"] in rule_descriptions:
                    finding["Description"] = rule_descriptions[finding["RuleID"]]
                    if verbose:
                        print(f"Updated description for rule {finding['RuleID']}: {finding['Description']}")
        
        # Generate JSON report
        if not findings:
            return JSONResponse(content=[])
            
        report = generate_report(
            findings=findings,
            output_format="json",
            redact=redact
        )
        
        # Return response
        if report is None:
            return JSONResponse(content=[])
        
        try:
            return JSONResponse(content=json.loads(report))
        except json.JSONDecodeError:
            # Fallback to returning the findings directly
            return JSONResponse(content=findings)
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error scanning repository: {str(e)}"
        )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


def main():
    """Run the API server."""
    # Check if config.ini exists in script directory or current directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if not (os.path.exists('config.ini') or os.path.exists(os.path.join(script_dir, 'config.ini'))):
        print("Warning: config.ini not found")
        print("Please create a config.ini file with the following format:")
        print("[GitHub]")
        print("token = your_github_token")
        print("repo = owner/repo")
        print("owner = owner")
    
    # Run server
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )


if __name__ == "__main__":
    main()
