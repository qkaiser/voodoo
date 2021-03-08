#!/usr/bin/env python3
'''
Generate SSID from MAC address similarly to Netgear CG3700B devices.

Author: Quentin Kaiser <kaiserquentin@gmail.com>
'''
import hashlib
import struct
import sys

SSID_PREFIX = "VOO-"

def get_ssid(mac):
    mac_candidate = "0x{}".format(mac.replace(":", "").upper())
    hash_value = bytearray(hashlib.md5(mac_candidate.encode("utf-8")).digest())
    return "{}{}".format(
        SSID_PREFIX,
        ''.join(
            [
                str(hash_value[i] % 10)\
                    for i in range(0, 6)
            ]
        )
    )

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} 00:11:22:33:44:55".format(sys.argv[1]))
        sys.exit(-1)
    print(get_ssid(sys.argv[1]))
