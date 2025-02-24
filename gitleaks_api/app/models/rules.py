from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class Rule(BaseModel):
    id: str
    description: str
    regex: str
    secretGroup: int = 1
    entropy: Optional[float] = None
    path: Optional[str] = None
    keywords: List[str] = []
    allowlist: Optional[Dict[str, Any]] = None
