from struct import pack, unpack
from dataclasses import dataclass
from typing import Tuple


MTU = 1500


def encode_mac(mac: str) -> bytes:
    return bytes([int(v, 16) for v in mac.split(":")])


def decode_mac(raw_mac: bytes) -> str:
    return ":".join([hex(v)[2:] for v in raw_mac])


def encode_ip(ip: str) -> bytes:
    return bytes([int(v) for v in ip.split(".")])


def decode_ip(raw_ip: bytes) -> str:
    return ".".join([str(v) for v in raw_ip])


def encode_tup(tup: Tuple[str, str]) -> Tuple[bytes, bytes]:
    mac, ip = tup
    raw_mac, raw_ip = encode_mac(mac), encode_ip(ip)
    return raw_mac, raw_ip


def decode_tup(raw_tup: Tuple[bytes, bytes]) -> Tuple[str, str]:
    raw_mac, raw_ip = raw_tup
    mac, ip = decode_mac(raw_mac), decode_ip(raw_ip)
    return mac, ip


INFO_PACKET_FORMAT = ">6s4s"


@dataclass(frozen=True)
class InfoPacket:
    mac: str
    ip: str

    def serialize(self) -> bytes:
        raw_mac, raw_ip = encode_mac(self.mac), encode_ip(self.ip)
        return pack(INFO_PACKET_FORMAT, raw_mac, raw_ip)

    @staticmethod
    def deserialize(raw: bytes) -> "InfoPacket":
        raw_mac, raw_ip = unpack(INFO_PACKET_FORMAT, raw)
        mac, ip = decode_mac(raw_mac), decode_ip(raw_ip)
        return InfoPacket(mac, ip)
