from services.vt_service import VirusTotalService
from services.detector_service import IOCType


result = VirusTotalService.lookup(
    "8.8.8.8",
    IOCType.IPV4
)


print(result)