from messages import InfoPacket
from dataclasses import dataclass
from socket import socket


@dataclass
class VpnSession:
    sock: socket

    mac: str
    ip: str

    def info(self) -> InfoPacket:
        return InfoPacket(self.mac, self.ip)
