#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
import zlib

# Initial message. The last byte is modified to 0xFF
payloads = [
    b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00",
    b"\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8",
    b"\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xff",
]
nb_frag = 3
packets = []

for i in range(nb_frag):
    # Read initial package
    arp = rdpcap('arp.cap')[0]

    # Cle wep AA:AA:AA:AA:AA
    key = b'\xaa\xaa\xaa\xaa\xaa'
    iv = b'\x00\x00\x00'

    # Set fragmented payloads
    plaintext = payloads[i]

    # Set "more_fragments" flag
    if i != nb_frag - 1:
        arp.FCfield |= 0b100

    # Set fragment number field
    arp.SC = i

    # Reset payload size. It'll be re-calculated when writing the package
    arp[RadioTap].len = None

    # Calculate CRC32
    icv = zlib.crc32(plaintext).to_bytes(4, byteorder='little')

    # Encrypt with RC4
    cipher = RC4(iv + key, streaming=False)
    ciphertext = cipher.crypt(plaintext + icv)

    # Set payload
    arp.wepdata = ciphertext[:-4]
    arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
    arp.iv = iv

    arp.show()
    packets.append(arp)

# Writing package to .pcap file
wrpcap('step3.pcap', packets)