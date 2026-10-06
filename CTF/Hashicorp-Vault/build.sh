#!/bin/bash
set -e

SRC="/mnt/g/My Drive/NT230/CTF/Hashicorp-Vault/source.c"
DIST="/mnt/g/My Drive/NT230/CTF/Hashicorp-Vault/dist"

BIN="$DIST/hashicorp-vault"
DBG="$DIST/hashicorp-vault-dbg"

mkdir -p "$DIST"

gcc -O0 -Wl,-z,relro,-z,now -pie -fPIE -o "$BIN" "$SRC"
strip "$BIN"

gcc -O0 -g -Wl,-z,relro,-z,now -pie -fPIE -o "$DBG" "$SRC"

echo "Build complete!"
