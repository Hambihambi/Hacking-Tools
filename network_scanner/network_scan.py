#!/usr/bin/env python3
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import argparse
import sys
import os

def root_check():
    if os.geteuid() != 0:
        sys.exit("[!] This script must run as root")
    else:
        print("[*] Welcome to the network scanner.")

def get_args():
    parser = argparse.ArgumentParser(
        description='Scan the network for MAC addresses by IP range',
        epilog='e.g.: networkscanner -i 192.168.56.1/24'
    )
    parser.add_argument(
        "-i", "--ip_range",
        dest="ip_range",
        required=True,
        help="the ip address to scan, e.g.: 192.168.0.1/24"
    )
    return parser.parse_args()

def scan(ip_range):
    try:
        print(f"[*] Creating ARP request for IP range: {ip_range}")
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast/arp_request
        print("[*] Sending broadcast ARP request...")
        answered_list = srp(packet, timeout=2, retry=1, verbose=False)[0]
        print(f"[*] Received {len(answered_list)} responses")
    except Exception as e:
        sys.exit(f"[!] Error scanning the network: {e}")

    return [{"ip": res[1].psrc, "mac": res[1].hwsrc} for res in answered_list]

def print_result(clients):
    print("[+] Scan Results:")
    print("[+] IP address".ljust(20, ".") + "MAC address")
    for client in clients:
        print(client["ip"].ljust(20) + client["mac"])

if __name__ == "__main__":
    root_check()
    args = get_args()
    print(f"[*] Starting scan on: {args.ip_range}")
    result = scan(args.ip_range)
    print_result(result)
    print("[*] Network scan completed.")
