#!/bin/bash
socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/ctf/rop-the-bank,pty,stderr,echo=0