from models.validation_result import ValidationResult
from services.detector_service import IOCType
import ipaddress
import socket
import requests
import re


class IOCValidator:

    HEX_PATTERN = re.compile(r"^[A-Fa-f0-9]+$")
    @classmethod
    def validate(
        cls,
        value: str,
        ioc_type: IOCType,
    ) -> ValidationResult:

        match ioc_type:

            case IOCType.IPV4:
                return cls.validate_ipv4(value)

            case IOCType.IPV6:
                return cls.validate_ipv6(value)

            case IOCType.DOMAIN:
                return cls.validate_domain(value)

            case IOCType.URL:
                return cls.validate_url(value)

            case IOCType.MD5:
                return cls.validate_md5(value)

            case IOCType.SHA1:
                return cls.validate_sha1(value)

            case IOCType.SHA256:
                return cls.validate_sha256(value)

            case _:
                return ValidationResult(
                    False,
                    "Unknown IOC"
                )

    @staticmethod
    def validate_ipv4(value: str):

        try:

            ip = ipaddress.ip_address(value)

            if ip.version != 4:

                return ValidationResult(
                    False,
                    "Not an IPv4 address"
                )

            return ValidationResult(
                True,
                "Valid IPv4"
            )

        except ValueError:

            return ValidationResult(
                False,
                "Invalid IPv4"
            )

    @staticmethod
    def validate_ipv6(value: str) -> ValidationResult:

        try:
            ip = ipaddress.ip_address(value)

            if ip.version != 6:
                return ValidationResult(
                    False,
                    "Not an IPv6 address"
                )

            return ValidationResult(
                True,
                "Valid IPv6"
            )

        except ValueError:
            return ValidationResult(
                False,
                "Invalid IPv6"
            )

    @classmethod
    def _validate_hash(
        cls,
        value: str,
        length: int,
        name: str
    ) -> ValidationResult:

        if len(value) != length:
            return ValidationResult(
                False,
                f"{name} length is invalid"
            )

        if not cls.HEX_PATTERN.fullmatch(value):
            return ValidationResult(
                False,
                f"{name} contains invalid characters"
            )

        return ValidationResult(
            True,
            f"Valid {name}"
        )
    @classmethod
    def validate_md5(cls, value: str):
        return cls._validate_hash(value, 32, "MD5")


    @classmethod
    def validate_sha1(cls, value: str):
        return cls._validate_hash(value, 40, "SHA1")


    @classmethod
    def validate_sha256(cls, value: str):
        return cls._validate_hash(value, 64, "SHA256")

    
    @staticmethod
    def validate_domain(value: str) -> ValidationResult:

        try:

            result = socket.getaddrinfo(value, None)
            ips = sorted({item[4][0] for item in result})

            return ValidationResult(
                True,
                f"Resolved ({', '.join(ips)})"
            )

        except socket.gaierror:

            return ValidationResult(
                False,
                "Domain could not be resolved"
            )

    @staticmethod
    def validate_url(value: str) -> ValidationResult:

        try:

            response = requests.head(
                value,
                timeout=5,
                allow_redirects=True
            )

            if response.status_code == 405:
                response = requests.get(
                    value,
                    timeout=5,
                    stream=True
                )

            return ValidationResult(
                True,
                f"HTTP {response.status_code}"
            )

        except requests.RequestException as e:

            return ValidationResult(
                False,
                str(e)
            )