from pydantic import BaseModel
from typing import Optional, List
import json

class Finding(BaseModel):
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
    Entropy: float = 3.75
    Author: str = ""
    Email: str = ""
    Date: str = ""
    Message: str = ""
    Tags: List[str] = []
    Fingerprint: str

    def __str__(self) -> str:
        """Format finding to match gitleaks output exactly."""
        return json.dumps({
            "RuleID": self.RuleID,
            "Description": self.Description,
            "StartLine": self.StartLine,
            "EndLine": self.EndLine,
            "StartColumn": self.StartColumn,
            "EndColumn": self.EndColumn,
            "Match": self.Match,
            "Secret": self.Secret,
            "File": self.File,
            "SymlinkFile": self.SymlinkFile,
            "Commit": self.Commit,
            "Link": self.Link,
            "Entropy": self.Entropy,
            "Author": self.Author,
            "Email": self.Email,
            "Date": self.Date,
            "Message": self.Message,
            "Tags": self.Tags,
            "Fingerprint": self.Fingerprint
        }, indent=1)
