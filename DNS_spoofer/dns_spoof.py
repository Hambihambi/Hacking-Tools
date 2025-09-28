#!/usr/bin/env python3

import netfilterqueue

def processpacket(packet):
    print(packet)
    # .drop or .access the packet
    packet.accept()

# create the object, bind to the iptables command and run
queue = netfilterqueue.NetfilterQueue()
queue.bind(1337, process_packet)
queue.run()
