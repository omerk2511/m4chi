from os import open, read, write, close, system, O_RDWR
from select import select
from struct import pack, unpack
from enum import IntEnum, IntFlag
from dataclasses import dataclass
from fcntl import ioctl
from typing_extensions import Literal
from messages import MTU


class IoctlCodes(IntEnum):
    TUNSETIFF = 0x400454CA


class InterfaceFlag(IntFlag):
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NAPI = 0x0010
    IFF_NAPI_FRAGS = 0x0020
    IFF_NO_PI = 0x1000
    IFF_ONE_QUEUE = 0x2000
    IFF_VNET_HDR = 0x4000
    IFF_TUN_EXCL = 0x8000
    IFF_MULTI_QUEUE = 0x0100
    IFF_ATTACH_QUEUE = 0x0200
    IFF_DETACH_QUEUE = 0x0400


IFF_NAME_SIZE = 16
IFF_REQ_FORMAT = f"<{IFF_NAME_SIZE}sH"


@dataclass(frozen=True)
class InterfaceRequest:
    name: str
    flags: InterfaceFlag

    def serialize(self) -> bytes:
        if len(self.name) > IFF_NAME_SIZE:
            raise AttributeError("interface name exceeding length limit")

        return pack(IFF_REQ_FORMAT, self.name.encode(), self.flags)

    @staticmethod
    def deserialize(raw: bytes) -> "InterfaceRequest":
        name, flags = unpack(IFF_REQ_FORMAT, raw)
        return InterfaceRequest(name.replace(b"\x00", b"").decode(),
                                InterfaceFlag(flags))


class VirtualInterface:
    def __init__(self, name: str, ip: str, mac: str):
        self.fd = open("/dev/net/tun", O_RDWR)

        request = InterfaceRequest(name, InterfaceFlag.IFF_TAP |
                                         InterfaceFlag.IFF_NO_PI)
        raw = ioctl(self.fd, IoctlCodes.TUNSETIFF, request.serialize())
        response = InterfaceRequest.deserialize(raw)

        self.name = response.name
        self.ip = ip
        self.mac = mac

        system(f"ip link set dev {self.name} address {self.mac}")
        system(f"ip addr add {self.ip}/24 dev {self.name}")
        system(f"ip link set {self.name} up")

    def __enter__(self) -> "VirtualInterface":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> Literal[False]:
        self.close()
        return False

    def close(self) -> None:
        close(self.fd)

    def send(self, packet: bytes) -> None:
        write(self.fd, packet)

    def recv(self) -> bytes:
        return read(self.fd, MTU)

    def ready(self) -> bool:
        ready, _, _ = select([self.fd], [], [], 0)
        return len(ready) != 0
