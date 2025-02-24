from typing import List, Generator, Optional, Dict, Any
import re
import math
try:
    # Try relative imports first (for module usage)
    from ..models.rules import Rule
    from ..models.findings import Finding
except ImportError:
    # Fall back to absolute imports (for direct file execution)
    from app.models.rules import Rule
    from app.models.findings import Finding

class Scanner:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
            
        entropy = 0.0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def _generate_fingerprint(self, path: str, line: int, rule_id: str) -> str:
        """Generate unique fingerprint for finding."""
        return f"{path}:{rule_id}:{line}"

    def scan_content(self, content: str, path: str = "", commit_info: Optional[Dict[str, Any]] = None) -> Generator[Finding, None, None]:
        for line_number, line in enumerate(content.splitlines(), 1):
            for rule in self.rules:
                match = re.search(rule.regex, line)
                if match:
                    # Calculate entropy
                    secret = match.group(rule.secretGroup)
                    entropy = self._calculate_entropy(secret)
                    
                    finding = Finding(
                        RuleID=rule.id,
                        Description=rule.description,
                        StartLine=line_number,
                        EndLine=line_number,
                        StartColumn=match.start() + 1,
                        EndColumn=match.end() + 1,
                        Match=match.group(0),
                        Secret=secret,
                        File=path,
                        SymlinkFile="",
                        Commit=commit_info.get('commit', '') if commit_info else '',
                        Link=None,  # Will be set by GitScanner if needed
                        Entropy=entropy,
                        Author=commit_info.get('author', '') if commit_info else '',
                        Email=commit_info.get('email', '') if commit_info else '',
                        Date=commit_info.get('date', '') if commit_info else '',
                        Message=commit_info.get('message', '') if commit_info else '',
                        Tags=rule.keywords,
                        Fingerprint=self._generate_fingerprint(path, line_number, rule.id)
                    )
                    yield finding
