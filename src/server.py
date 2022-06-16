#!/usr/bin/python3


from argparse import ArgumentParser
from socket import socket
from select import select
from os import urandom
from typing import List, Tuple
from messages import decode_mac, InfoPacket


def main() -> None:
    parser = ArgumentParser(description="m4gnum's vpn server")

    parser.add_argument("ip", type=str, help="vpn server's ip")
    parser.add_argument("port", type=int, help="vpn server's port")
    parser.add_argument("--base", type=str, help="vpn ip range base", default="172.20.20")

    args = parser.parse_args()

    sock = socket()
    sock.bind((args.ip, args.port))
    sock.listen(5)

    sessions: List[Tuple[socket, int]] = []
    options = {v for v in range(256)} - {0, 255}

    while True:
        ready, _, _ = select([sock], [], [], 0)
        if ready:
            session, addr = sock.accept()
            suffix = options.pop()
            sessions.append((session, suffix))

            mac = decode_mac(urandom(6))
            ip = f"{args.base}.{suffix}"
            info = InfoPacket(mac, ip)

            # TODO:: announce via arp?
            session.send(info.serialize())

        ready, _, _ = select([s for s, _ in sessions], [], [], 0)
        for session in ready:
            pkt = session.recv(1500)
            if not pkt:
                _, suffix = [(s, o) for s, o in sessions if s is session].pop()
                options.add(suffix)
                session.close()
                sessions.remove((session, suffix))
                continue

            # TODO:: virtual hub -> virtual switch
            relevant = [s for s, _ in sessions if s is not session]
            for s in relevant:
                s.send(pkt)


if __name__ == "__main__":
    main()
