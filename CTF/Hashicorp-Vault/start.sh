#!/bin/sh
exec socat TCP-LISTEN:1111,reuseaddr,fork EXEC:/home/ctf/hashicorp-vault,stderr