from session import VpnSession
from packets import Ether, ARP, BROADCAST_MAC
from messages import MTU, decode_mac
from socket import socket
from select import select
from os import urandom
from typing import Dict, Set
from typing_extensions import Literal


# TODO:: ip pool
RESERVED_SUFFIXES = {0, 255}
SUFFIX_LIMIT = 256


class VpnSwitch:
    def __init__(self, ip: str, port: int, base: str):
        self.socket = socket()
        self.socket.bind((ip, port))
        self.socket.listen(5)

        self.base = base
        self.suffixes = {v for v in range(SUFFIX_LIMIT)} - RESERVED_SUFFIXES

        self.cam: Dict[str, VpnSession] = {}

    def __enter__(self) -> "VpnSwitch":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> Literal[False]:
        self.close()
        return False

    def close(self) -> None:
        self.socket.close()

    def pending(self) -> bool:
        ready, _, _ = select([self.socket], [], [], 0)
        return len(ready) != 0

    def accept(self) -> None:
        sock, addr = self.socket.accept()

        # TODO:: manage via pool as well
        mac = decode_mac(b"\xfc\xd8\x47" + urandom(3))

        suffix = self.suffixes.pop()
        ip = f"{self.base}.{suffix}"

        session = VpnSession(sock, mac, ip)

        arp_announcement = ARP.announce(mac, ip).serialize()
        for current in self.cam.values():
            current.sock.send(arp_announcement)

        self.cam[mac] = session
        sock.send(session.info().serialize())

    def ready(self) -> Set[str]:
        ready, _, _ = select([session.sock for session in self.cam.values()], [], [], 0)

        ready_macs: Set[str] = set()
        for mac, session in self.cam.items():
            if session.sock not in ready:
                continue
            ready_macs.add(mac)

        return ready_macs

    def drain(self) -> None:
        for mac in self.ready():
            session = self.cam[mac]
            pkt = session.sock.recv(MTU)

            if not pkt:
                # TODO:: pool.free(session.ip)
                del self.cam[mac]
                continue

            ether = Ether.deserialize(pkt)
            for current in self.cam.values():
                if current is session:
                    continue
                if ether.dst != current.mac and ether.dst != BROADCAST_MAC:
                    continue
                current.sock.send(pkt)
