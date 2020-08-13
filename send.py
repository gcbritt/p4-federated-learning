#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
import readline

class P4inc(Packet):
    name = "P4inc"
    fields_desc = [ StrFixedLenField("P", "P", length=1), # P
                    StrFixedLenField("Four", "4", length=1), # 4
                    XByteField("version", 0x01), # version
		    XByteField("bos", 0x00), # bottom of stack, last packet 0/1
                    IntField("data", 0), # data packet
		    IntField("result", 112)] # aggregated data

bind_layers(IP, P4inc, version=4L)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    while True:
	strn = str(raw_input('Enter a number to send to host. Type \'quit\' to quit>:'))
	first_packet = str(raw_input('Is this the first packet? y/n >:'))
	last_packet = str(raw_input('Is this the last packet? y/n >:'))
		
	if strn is "quit":
	    break       

	addr = socket.gethostbyname(sys.argv[1])
	iface = get_if()

	print "sending on interface %s to %s" % (iface, str(addr))
	pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
	#pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / strn

	if first_packet is "y":
		pkt = pkt /IP(dst=addr) / P4inc(data=int(strn), result=0)
	elif last_packet is "y":
		pkt = pkt /IP(dst=addr) / P4inc(bos=0x01, data=int(strn))
	else:
		pkt = pkt /IP(dst=addr) / P4inc(data=int(strn))
		
	pkt.show2()
	sendp(pkt, iface=iface, verbose=False)
	print("packet sent...")


if __name__ == '__main__':
    main()
