import ipaddress
import re
from enum import Enum
from urllib.parse import urlparse


class IOCType(Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "Domain"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    UNKNOWN = "Unknown"


class IOCDetector:

    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    )

    HASH_REGEX = re.compile(r"^[A-Fa-f0-9]+$")

    @classmethod
    def detect(cls, value: str) -> IOCType:

        value = value.strip()

        if not value:
            return IOCType.UNKNOWN

        if cls._is_url(value):
            return IOCType.URL

        if cls._is_ip(value):
            return cls._ip_type(value)

        if cls._is_hash(value):
            return cls._hash_type(value)

        if cls._is_domain(value):
            return IOCType.DOMAIN

        return IOCType.UNKNOWN

    @staticmethod
    def _is_url(value: str) -> bool:

        try:

            result = urlparse(value)

            return all([result.scheme, result.netloc])

        except Exception:

            return False

    @staticmethod
    def _is_ip(value: str) -> bool:

        try:

            ipaddress.ip_address(value)

            return True

        except ValueError:

            return False
    
    @staticmethod
    def _ip_type(value: str) -> IOCType:

        ip = ipaddress.ip_address(value)

        if ip.version == 4:

            return IOCType.IPV4

        return IOCType.IPV6    

    @classmethod
    def _is_hash(cls, value: str) -> bool:

        return bool(cls.HASH_REGEX.fullmatch(value))

    @staticmethod
    def _hash_type(value: str) -> IOCType:

        length = len(value)

        if length == 32:
            return IOCType.MD5

        if length == 40:
            return IOCType.SHA1

        if length == 64:
            return IOCType.SHA256

        return IOCType.UNKNOWN

    @classmethod
    def _is_domain(cls, value: str) -> bool:

        return bool(cls.DOMAIN_REGEX.fullmatch(value))