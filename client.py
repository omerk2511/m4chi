#!/usr/bin/python3


from os import open, read, write, close, system, O_RDWR
from socket import socket
from select import select
from struct import pack, unpack
from argparse import ArgumentParser
from enum import IntEnum, IntFlag
from dataclasses import dataclass
from fcntl import ioctl
from typing import Tuple
from typing_extensions import Literal


def encode_mac(mac: str) -> bytes:
    return bytes([int(v, 16) for v in mac.split(":")])


def decode_mac(raw_mac: bytes) -> str:
    return ":".join([hex(v)[2:] for v in raw_mac])


def encode_ip(ip: str) -> bytes:
    return bytes([int(v) for v in ip.split(".")])


def decode_ip(raw_ip: bytes) -> str:
    return ".".join([str(v) for v in raw_ip])


MTU = 1500

INFO_PACKET_FORMAT = ">6s4s"


class VpnEndpoint:
    def __init__(self, ip: str, port: int):
        self.socket = socket()
        self.socket.connect((ip, port))

        info = self.recv()
        raw_mac, raw_ip = unpack(INFO_PACKET_FORMAT, info)
        self.mac, self.ip = decode_mac(raw_mac), decode_ip(raw_ip)

    def __enter__(self) -> "VpnEndpoint":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> Literal[False]:
        self.close()
        return False

    def close(self) -> None:
        self.socket.close()

    def send(self, packet: bytes) -> None:
        self.socket.send(packet)

    def recv(self) -> bytes:
        return self.socket.recv(MTU)

    def ready(self) -> bool:
        ready, _, _ = select([self.socket], [], [], 0)
        return len(ready) != 0


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


class EtherType(IntEnum):
    ARP = 0x806
    IPV4 = 0x800
    IPV6 = 0x86DD


ETHER_HEADER_FORMAT = ">6s6sH"
ETHER_HEADER_LEN = 14


@dataclass(frozen=True)
class EtherFrame:
    dst: str
    src: str
    typ: EtherType
    payload: bytes

    def serialize(self) -> bytes:
        raw_dst, raw_src = encode_mac(self.dst), encode_mac(self.src)
        return pack(ETHER_HEADER_FORMAT, raw_dst, raw_src, self.typ) + self.payload

    @staticmethod
    def deserialize(raw: bytes) -> "EtherFrame":
        raw_dst, raw_src, typ = unpack(ETHER_HEADER_FORMAT, raw[:ETHER_HEADER_LEN])
        dst, src = decode_mac(raw_dst), decode_mac(raw_src)
        return EtherFrame(dst, src, typ, raw[ETHER_HEADER_LEN:])


class ArpOperation(IntEnum):
    REQUEST = 1
    REPLY = 2


ARP_PACKET_FORMAT = ">HHBBH6s4s6s4s"


def encode_tup(tup: Tuple[str, str]) -> Tuple[bytes, bytes]:
    mac, ip = tup
    raw_mac, raw_ip = encode_mac(mac), encode_ip(ip)
    return raw_mac, raw_ip


def decode_tup(raw_tup: Tuple[bytes, bytes]) -> Tuple[str, str]:
    raw_mac, raw_ip = raw_tup
    mac, ip = decode_mac(raw_mac), decode_ip(raw_ip)
    return mac, ip


@dataclass(frozen=True)
class ArpPacket:
    operation: ArpOperation
    src: Tuple[str, str]
    dst: Tuple[str, str]

    def serialize(self) -> bytes:
        raw_src, raw_dst = encode_tup(self.src), encode_tup(self.dst)
        return pack(ARP_PACKET_FORMAT, 1, 0x800, 6, 4, self.operation, *raw_src, *raw_dst)

    @staticmethod
    def deserialize(raw: bytes) -> "ArpPacket":
        _, _, _, _, operation, raw_src_mac, raw_src_ip, raw_dst_mac, raw_dst_ip = unpack(ARP_PACKET_FORMAT, raw)
        raw_src, raw_dst = (raw_src_mac, raw_src_ip), (raw_dst_mac, raw_dst_ip)
        src, dst = decode_tup(raw_src), decode_tup(raw_dst)
        return ArpPacket(operation, src, dst)


def main() -> None:
    parser = ArgumentParser(description="m4gnum's vpn client")

    parser.add_argument("iface", type=str, help="iface identifier")
    parser.add_argument("ip", type=str, help="vpn server's ip")
    parser.add_argument("port", type=int, help="vpn server's port")

    args = parser.parse_args()

    with VpnEndpoint(args.ip, args.port) as vpn:
        with VirtualInterface(args.iface, vpn.ip, vpn.mac) as iff:
            print(f"[+] up @ {iff.name}")
            while True:
                if iff.ready():
                    pkt = iff.recv()
                    print(f"[*] iff->vpn: {EtherFrame.deserialize(pkt)}")
                    vpn.send(pkt)
                if vpn.ready():
                    pkt = vpn.recv()
                    print(f"[*] vpn->iff: {EtherFrame.deserialize(pkt)}")
                    iff.send(pkt)


if __name__ == "__main__":
    main()
