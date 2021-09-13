#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host auto-pwn.chal.csaw.io --port 11001
from pwn import *
from binascii import unhexlify
import re

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './path/to/binary'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'auto-pwn.chal.csaw.io'
port = int(args.PORT or 11002)

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

pattern = re.compile("^[0-9,a-f]{4}$")

io = start()

io.sendlineafter(b">", b"4a47f4618ce3e7b567cce92b48f41e61")
io.recvuntil(b"-------------------------------------------------------------------\n")

vuln = b""

while True:
    line = io.recvline()

    if b"-------------------------------------------------------------------\n" in line:
        break

    dump = line.split()[1:9]

    for i in dump:
        if not pattern.match(i.decode()):
            break

        vuln += unhexlify(i)

f = open('./vuln', 'wb')
f.write(vuln)
f.close()

io.interactive()

