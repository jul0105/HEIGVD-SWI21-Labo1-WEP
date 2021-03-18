#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Julien Béguin & Gwendoline Dössegger"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
from rc4 import RC4
import zlib


# Read initial package
arp = rdpcap('arp.cap')[0]

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
iv = b'\x00\x00\x00'

# Initial message. The last byte is modified to 0xFF
plaintext = b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xff"

# Calculate CRC32
icv = zlib.crc32(plaintext).to_bytes(4, byteorder='little')

# Encrypt with RC4
cipher = RC4(iv + key, streaming=False)
ciphertext = cipher.crypt(plaintext + icv)

# Set payload
arp.wepdata = ciphertext[:-4]
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
arp.iv = iv

# Writing package to .pcap file
wrpcap('step2.pcap', arp)
