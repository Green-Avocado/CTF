#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1421 encode-me.py
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'encode-me.py'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1421)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def encode_bytes(x):
    return x.to_bytes(8, 'little')

def encode_base64(x):
    return base64.b64encode(x.to_bytes(8, 'big'))

def encode_hex(x):
    return hex(x).encode()

def encode_binary(x):
    return bin(x).encode()

encodings = {
        'bytes (little endian)': encode_bytes,
        'base64': encode_base64,
        'hexadecimal': encode_hex,
        'binary': encode_binary,
    }

io = start()

for i in range(1337):
    print(io.recvuntil(b"Return "))

    number = int(io.recvuntil(b" as ", drop=True))
    encoding = io.recvuntil(b"\n", drop=True).decode()

    io.sendlineafter(b"Encoded number: ", encodings[encoding](number))

io.interactive()

