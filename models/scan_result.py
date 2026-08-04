from dataclasses import dataclass

from services.detector_service import IOCType
from models.validation_result import ValidationResult
from models.vt_result import VTResult


@dataclass(slots=True)
class ScanResult:

    value: str

    ioc_type: IOCType

    validation: ValidationResult

    vt_result: VTResult | None = None