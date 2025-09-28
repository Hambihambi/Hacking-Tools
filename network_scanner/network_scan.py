#!/usr/bin/env python3
import scapy.all as scapy
import argparse


def get_args():
    parser = argparse.ArgumentParser(description='Scan the network for MAC addresses by IP range', epilog='e.g.: networkscanner -i 192.168.0.1/24')
    parser.add_argument("-i", "--ip_address", dest="ip_address", required=True, help="the ip address to scan, e.g.: 192.168.0.1/24")
    args = parser.parse_args()
    return args


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    return client_list


def print_result(result_list):
    print("IP address" + "\t\t" + "MAC address" + "\n")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


arguments = get_args()
scan_result = scan(arguments.ip_address)
print_result(scan_result)
