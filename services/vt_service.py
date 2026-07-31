import base64

import requests

from config import VT_API_KEY

from services.detector_service import IOCType

from models.vt_result import VTResult

ENDPOINTS = {

    IOCType.IPV4: "/ip_addresses/{value}",

    IOCType.IPV6: "/ip_addresses/{value}",

    IOCType.DOMAIN: "/domains/{value}",

    IOCType.SHA256: "/files/{value}",

    IOCType.SHA1: "/files/{value}",

    IOCType.MD5: "/files/{value}",
}

class VirusTotalService:

    BASE_URL = "https://www.virustotal.com/api/v3"

    TIMEOUT = 15


    _session = requests.Session()

    _session.headers.update(
        {
            "x-apikey": VT_API_KEY
        }
    )


    @classmethod
    def lookup(
        cls,
        value: str,
        ioc_type: IOCType
    ) -> VTResult:

        match ioc_type:

            case IOCType.URL:

                return cls._lookup_url(value)


            case _:

                return cls._lookup_standard(
                    value,
                    ioc_type
                )


    @classmethod
    def _lookup_standard(
        cls,
        value: str,
        ioc_type: IOCType
    ) -> VTResult:


        endpoint = ENDPOINTS.get(ioc_type)


        if not endpoint:

            return VTResult(
                False,
                "Unsupported IOC type"
            )


        url = cls.BASE_URL + endpoint.format(
            value=value
        )


        response = cls._request(url)


        if response is None:

            return VTResult(
                False,
                "VirusTotal request failed"
            )


        return cls._parse_response(response)

    @classmethod
    def _lookup_url(
        cls,
        value: str
    ) -> VTResult:


        url_id = base64.urlsafe_b64encode(
            value.encode()
        ).decode().strip("=")


        endpoint = f"/urls/{url_id}"


        url = cls.BASE_URL + endpoint


        response = cls._request(url)


        if response is None:

            return VTResult(
                False,
                "VirusTotal URL lookup failed"
            )


        return cls._parse_response(response)


    @classmethod
    def _request(
        cls,
        url: str
    ):


        try:

            response = cls._session.get(
                url,
                timeout=cls.TIMEOUT
            )


            response.raise_for_status()


            return response.json()


        except requests.Timeout:

            return None


        except requests.HTTPError:

            return None


        except requests.RequestException:

            return None
    @classmethod
    def _parse_response(
        cls,
        data: dict
    ) -> VTResult:


        try:

            stats = (
                data
                ["data"]
                ["attributes"]
                ["last_analysis_stats"]
            )


            return VTResult(

                success=True,

                message="Analysis completed",

                malicious=stats.get(
                    "malicious",
                    0
                ),

                harmless=stats.get(
                    "harmless",
                    0
                ),

                suspicious=stats.get(
                    "suspicious",
                    0
                ),

                undetected=stats.get(
                    "undetected",
                    0
                ),

                timeout=stats.get(
                    "timeout",
                    0
                )
            )


        except KeyError:


            return VTResult(
                False,
                "Invalid VirusTotal response"
            )