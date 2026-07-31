from dataclasses import dataclass, field


@dataclass(slots=True)
class VTResult:

    success: bool

    message: str

    malicious: int = 0

    harmless: int = 0

    suspicious: int = 0

    undetected: int = 0

    timeout: int = 0