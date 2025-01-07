section .text
global _start

_start:
	push 0x00
	mov eax, 0x68732F6E
	push eax
	mov eax, 0x69622F00
	push eax

	xor edx, edx
	xor ecx, ecx
	mov ebx, esp
	mov eax, 0xb
	syscall	
