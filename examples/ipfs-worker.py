import ipaddress
import json
from csv import reader

import requests

from teatime import NodeType, Scanner
from teatime.plugins.ipfs import CommandCheck

TARGET_FILE = "/home/spoons/Downloads/peerIPs.csv"
DEFAULT_PORT = 5001


def teatime_scan(ip):
    s = Scanner(
        ip=ip,
        port=DEFAULT_PORT,
        node_type=NodeType.IPFS,
        plugins=[CommandCheck()],
    )
    return s.run()


if __name__ == "__main__":
    with open(TARGET_FILE) as f_target:
        target_list = set()
        for row in reader(f_target):
            target_list.add(row[1].split(":")[0])

    # target_list = {"136.144.57.15"}
    print(f"[+] Got {len(target_list)} entries")
    target_list = [x for x in target_list if x != ""]

    for ip in list(target_list):
        try:
            ip: ipaddress.IPv4Address = ipaddress.IPv4Address(ip)
        except ValueError as e:
            # not a valid IPv4
            print("meh", e)
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip == ipaddress.IPv4Address("127.0.0.1")
        ):
            print("nope")
            continue

        try:
            resp = requests.post(f"http://{ip}:{DEFAULT_PORT}/api/v0/id", timeout=3)
            if resp.status_code != 200:
                raise ValueError
        except:
            print("Connection failed")
            continue

        print(f"[+] Discovered open service at {ip}:{DEFAULT_PORT}")
        report = teatime_scan(str(ip))

        with open(f"{ip}.json", "w+") as f_report:
            json.dump(report.to_dict(), f_report, indent=2, sort_keys=True)
