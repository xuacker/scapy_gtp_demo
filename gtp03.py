#!/usr/bin/python

from scapy.all import Ether,IP,UDP,DNS,DNSRR,sendp, conf
from scapy.contrib import gtp

# from scapy_http import http
import pcap
import sys
import socket
teids = {}

conf.verb = 0
s = conf.L2socket(iface=sys.argv[4])

def usage():
    print "program  -i pcap | interface  -t interface"
    sys.exit()

def main():
    sniffer = pcap.pcap(sys.argv[2], snaplen=65535)
    sniffer.setfilter("ip")
    for ts, pkt in sniffer:
        pkt1 = IP(str(pkt)[14:])
        outpkt = Ether(dst="80:fa:5b:3e:f2:4a", src="98:54:1b:a1:fc:70")/\
            IP(dst="1.1.1.1", src="2.2.2.2")/\
            UDP(dport=2152, sport=2158)/\
            gtp.GTP_U_Header(version=1, PT=1, S=1, teid=1, length=len(pkt1)+4)/pkt1
        try:
            s.send(outpkt)
        except socket.error:
            pass


if __name__ == "__main__":
    main()
