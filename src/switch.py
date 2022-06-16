from session import VpnSession
from pool import AddressPool
from packets import Ether, ARP, BROADCAST_MAC
from messages import MTU
from socket import socket
from select import select
from typing import Dict, Set
from typing_extensions import Literal


class VpnSwitch:
    def __init__(self, ip: str, port: int, base: str, vendor: str):
        self.socket = socket()
        self.socket.bind((ip, port))
        self.socket.listen(5)

        self.pool = AddressPool(base, vendor)
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

        mac, ip = self.pool.alloc()
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
                del self.cam[mac]
                self.pool.free((session.mac, session.ip))
                continue

            ether = Ether.deserialize(pkt)
            for current in self.cam.values():
                if current is session:
                    continue
                if ether.dst != current.mac and ether.dst != BROADCAST_MAC:
                    continue
                current.sock.send(pkt)
