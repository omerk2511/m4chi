#!/usr/bin/python3


from argparse import ArgumentParser
from endpoint import VpnEndpoint
from tap import VirtualInterface
from packets import Ether


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
                    print(f"[*] iff->vpn: {Ether.deserialize(pkt)}")
                    vpn.send(pkt)
                if vpn.ready():
                    pkt = vpn.recv()
                    print(f"[*] vpn->iff: {Ether.deserialize(pkt)}")
                    iff.send(pkt)


if __name__ == "__main__":
    main()
