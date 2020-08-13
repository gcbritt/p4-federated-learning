#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, StrFixedLenField, XByteField
from scapy.all import IP, TCP, UDP, Raw
from scapy.all import bind_layers
from scapy.layers.inet import _IPOption_HDR

class P4inc(Packet):
    name = "P4inc"
    fields_desc = [ StrFixedLenField("P", "P", length=1), # P
                    StrFixedLenField("Four", "4", length=1), # 4
                    XByteField("version", 0x01), # version
		    XByteField("bos", 0x00),
                    IntField("data", 0),
		    IntField("result", 0)]

bind_layers(IP, P4inc, version=4L)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
   if P4inc in pkt and pkt[P4inc].version == 0x01:
   	print "got a packet"
   	pkt.show2()
    #    hexdump(pkt)
   	sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
