#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_processer)

def packet_processer(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)

sniff("eth0")
