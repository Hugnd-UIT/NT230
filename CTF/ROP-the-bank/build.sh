#!/bin/bash
set -e

SRC="/mnt/g/My Drive/NT230/CTF/ROP-the-bank/source.c"
DIST="/mnt/g/My Drive/NT230/CTF/ROP-the-bank/dist"
LIB="/mnt/g/My Drive/NT230/CTF/ROP-the-bank/lib"

BIN="$DIST/rop-the-bank"
DBG="$DIST/rop-the-bank-dbg"


mkdir -p "$DIST"


gcc -O0 \
    -fstack-protector-all \
    -pie -fPIE \
    -Wl,-z,relro,-z,now \
    -Wl,-z,noexecstack \
    -Wno-stringop-overflow \
    -Wno-stringop-overread \
    -s \
    -o "$BIN" "$SRC"


gcc -O0 \
    -fstack-protector-all \
    -pie -fPIE \
    -Wl,-z,relro,-z,now \
    -Wl,-z,noexecstack \
    -Wno-stringop-overflow \
    -Wno-stringop-overread \
    -g \
    -o "$DBG" "$SRC"


LIBC_SYS=$(ldd "$BIN" | grep 'libc.so' | awk '{print $3}')
LD_SYS=$(ldd "$BIN"   | grep 'ld-linux' | awk '{print $1}')

mkdir -p "$LIB"
cp "$LIBC_SYS" "$LIB/libc.so.6"
cp "$LD_SYS"   "$LIB/ld-linux-x86-64.so.2"


checksec --file="$BIN"


ROPgadget --binary "$DBG" 2>/dev/null | grep ': pop rdi ; ret' | head -3

objdump -d "$DBG" | grep -E '@plt>:' | head -10

objdump -R "$DBG" | grep -E 'printf|puts' | head -5

nm "$DBG" | grep -E '\bdeposit\b|\bshow_statement\b|\bmenu\b|\bapply_withdrawal\b' | sort