from socket import socket
from select import select
from typing_extensions import Literal
from messages import MTU, InfoPacket


class VpnEndpoint:
    def __init__(self, ip: str, port: int):
        self.socket = socket()
        self.socket.connect((ip, port))

        info = InfoPacket.deserialize(self.recv())
        self.mac, self.ip = info.mac, info.ip

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
