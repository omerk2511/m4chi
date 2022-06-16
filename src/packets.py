from struct import pack, unpack
from enum import IntEnum
from dataclasses import dataclass
from typing import Tuple
from messages import encode_mac, decode_mac, encode_tup, decode_tup


NULL_MAC = "00:00:00:00:00:00"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


class EtherType(IntEnum):
    ARP = 0x806
    IPV4 = 0x800
    IPV6 = 0x86DD


ETHER_HEADER_FORMAT = ">6s6sH"
ETHER_HEADER_LEN = 14


@dataclass(frozen=True)
class Ether:
    dst: str
    src: str
    typ: EtherType
    payload: bytes

    def serialize(self) -> bytes:
        raw_dst, raw_src = encode_mac(self.dst), encode_mac(self.src)
        return pack(ETHER_HEADER_FORMAT, raw_dst, raw_src, self.typ) + self.payload

    @staticmethod
    def deserialize(raw: bytes) -> "Ether":
        raw_dst, raw_src, typ = unpack(ETHER_HEADER_FORMAT, raw[:ETHER_HEADER_LEN])
        dst, src = decode_mac(raw_dst), decode_mac(raw_src)
        return Ether(dst, src, typ, raw[ETHER_HEADER_LEN:])

    @staticmethod
    def broadcast(src: str, typ: EtherType, payload: bytes) -> "Ether":
        return Ether(BROADCAST_MAC, src, typ, payload)


class ArpOperation(IntEnum):
    REQUEST = 1
    REPLY = 2


ARP_PACKET_FORMAT = ">HHBBH6s4s6s4s"


@dataclass(frozen=True)
class ARP:
    operation: ArpOperation
    src: Tuple[str, str]
    dst: Tuple[str, str]

    def serialize(self) -> bytes:
        raw_src, raw_dst = encode_tup(self.src), encode_tup(self.dst)
        return pack(ARP_PACKET_FORMAT, 1, 0x800, 6, 4, self.operation, *raw_src, *raw_dst)

    @staticmethod
    def deserialize(raw: bytes) -> "ARP":
        _, _, _, _, operation, raw_src_mac, raw_src_ip, raw_dst_mac, raw_dst_ip = unpack(ARP_PACKET_FORMAT, raw)
        raw_src, raw_dst = (raw_src_mac, raw_src_ip), (raw_dst_mac, raw_dst_ip)
        src, dst = decode_tup(raw_src), decode_tup(raw_dst)
        return ARP(operation, src, dst)

    @staticmethod
    def announce(mac: str, ip: str) -> "Ether":
        src, dst = (mac, ip), (NULL_MAC, ip)
        arp = ARP(ArpOperation.REQUEST, src, dst)
        return Ether.broadcast(mac, EtherType.ARP, arp.serialize())
