from dataclasses import dataclass
from typing import Any

@dataclass(slots=True)
class ValidationResult:
    is_valid: bool
    message: str
    details: dict[str, Any] | None = None