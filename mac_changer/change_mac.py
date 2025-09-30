#!/usr/bin/env python3

import subprocess
import argparse
import re
import os
import sys

def root_check():
    if os.geteuid() != 0:
        sys.exit("[!] This script must run as root")

def get_args():
    parser = argparse.ArgumentParser(description="Change MAC address of a network interface")
    parser.add_argument("-i", "--interface", required=True, help="Interface to change the MAC address of")
    parser.add_argument("-m", "--mac", required=True, help="MAC address to change to")
    return parser.parse_args()

def validate_mac(mac):
    if not re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
        sys.exit("[!] Invalid MAC address format")

def change_mac(interface, new_mac):
    subprocess.run(["ip", "link", "set", "dev", interface, "down"], check=True)
    subprocess.run(["ip", "link", "set", "dev", interface, "address", new_mac], check=True)
    subprocess.run(["ip", "link", "set", "dev", interface, "up"], check=True)

def get_current_mac(interface):
    result = subprocess.check_output(["ip", "link", "show", interface], encoding="utf-8")
    match = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", result)
    return match.group(0) if match else None

if __name__ == "__main__":
    root_check()
    args = get_args()
    validate_mac(args.mac)

    print(f"[+] Current MAC of {args.interface}: {get_current_mac(args.interface)}")
    change_mac(args.interface, args.mac)
    new_mac = get_current_mac(args.interface)

    if new_mac == args.mac:
        print(f"[*] MAC address of {args.interface} changed successfully to {new_mac}")
    else:
        print("[!] Failed to change MAC address")
