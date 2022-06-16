from messages import decode_mac
from typing import Set, Tuple
from os import urandom


RESERVED_SUFFIXES = {0, 255}
SUFFIX_LIMIT = 256

MAC_DEVICE_BYTES = 3


class AddressPool:
    def __init__(self, base: str, vendor: str):
        self.base = base
        self.vendor = bytes([int(v, 16) for v in vendor.split(":")])

        self.suffixes = {suffix for suffix in range(SUFFIX_LIMIT)} - RESERVED_SUFFIXES
        self.macs: Set[str] = set()

    def alloc_mac(self) -> str:
        while True:
            raw_mac = self.vendor + urandom(MAC_DEVICE_BYTES)
            mac = decode_mac(raw_mac)

            if mac in self.macs:
                continue

            self.macs.add(mac)
            return mac

    def alloc_ip(self) -> str:
        suffix = self.suffixes.pop()
        return f"{self.base}.{suffix}"

    def alloc(self) -> Tuple[str, str]:
        return self.alloc_mac(), self.alloc_ip()

    def free(self, tup: Tuple[str, str]) -> None:
        mac, ip = tup
        suffix = int(ip.split(".")[-1])

        self.suffixes.add(suffix)
        self.macs.remove(mac)
