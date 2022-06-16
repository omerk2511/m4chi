#!/usr/bin/python3


from argparse import ArgumentParser
from switch import VpnSwitch


def main() -> None:
    parser = ArgumentParser(description="m4gnum's vpn server")

    parser.add_argument("ip", type=str, help="vpn server's ip")
    parser.add_argument("port", type=int, help="vpn server's port")
    parser.add_argument("--base", type=str, help="vpn ip range base", default="172.20.20")
    parser.add_argument("--vendor", type=str, help="vpn mac address vendor id", default="fc:d8:47")

    args = parser.parse_args()

    with VpnSwitch(args.ip, args.port, args.base, args.vendor) as switch:
        print(f"[+] up @ {args.base}.0/24")
        while True:
            if switch.pending():
                switch.accept()
            switch.drain()


if __name__ == "__main__":
    main()
