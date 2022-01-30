#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1420 decode-me.py
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'decode-me.py'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1420)

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

import base64

def decode_bytes(x):
    return u64(x)

def decode_base64(x):
    return int.from_bytes(base64.b64decode(x.decode()), "big")

def decode_hex(x):
    return int(x.decode(), 0)

def decode_binary(x):
    return int(x.decode(), 0)

decode_funcs = {
        'BYTES (LITTLE ENDIAN)': decode_bytes,
        'BASE64': decode_base64,
        'HEXADECIMAL': decode_hex,
        'BINARY': decode_binary,
    }

io = start()

for i in range(1337):
    io.recvuntil(b"-----BEGIN ")

    encoding = io.recvuntil(b" ENCODED MESSAGE-----\n", drop=True).decode()
    message = io.recvuntil(b"\n-----END", drop=True)

    io.sendlineafter(b"Decoded number: ", str(decode_funcs[encoding](message)).encode())

io.interactive()

