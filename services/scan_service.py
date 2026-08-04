from models.scan_result import ScanResult

from services.detector_service import IOCDetector
from services.validator_service import IOCValidator
from services.vt_service import VirusTotalService


class ScanService:

    @classmethod
    def scan(cls, value: str) -> ScanResult:

        value = value.strip()

        ioc_type = IOCDetector.detect(value)

        validation = IOCValidator.validate(
            value,
            ioc_type
        )

        if not validation.is_valid:

            return ScanResult(
                value=value,
                ioc_type=ioc_type,
                validation=validation,
                vt_result=None
            )

        vt_result = VirusTotalService.lookup(
            value,
            ioc_type
        )

        return ScanResult(
            value=value,
            ioc_type=ioc_type,
            validation=validation,
            vt_result=vt_result
        )