# Compress The Flag

## Challenge

If we connect to the server, it prompts us for a seed and a string.

The server uses the seed to randomly scramble the characters in the flag, then append the result to the string we gave.

Then, the server returns the length of the new string, and the lengths of the string when compressed using zlib, bzip2, and lzma.

## Solution

Compression algorithms will simplify patterns such as repeated characters.

For example, if we enter 100 "A"s as our string, the result looks like this:

```
-> % nc compresstheflag.hackable.software 1337
Please send: seed:string\n
I'll then show you the compression benchmark results!
Note: Flag has format DrgnS{[A-Z]+}
0:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    none  125
    zlib   37
   bzip2   67
    lzma   92

```

All compression algorithms are able to represent this pattern such that the result requires less space than the raw string.

Through trial and error, we find that zlib, as it is implemented in this challenge, will compress a string of repeated characters if the length is at least 5:

```
-> % nc compresstheflag.hackable.software 1337
Please send: seed:string\n
I'll then show you the compression benchmark results!
Note: Flag has format DrgnS{[A-Z]+}
0:@@@@
    none   29
    zlib   37
   bzip2   68
    lzma   88

-> % nc compresstheflag.hackable.software 1337
Please send: seed:string\n
I'll then show you the compression benchmark results!
Note: Flag has format DrgnS{[A-Z]+}
0:@@@@@
    none   30
    zlib   36
   bzip2   68
    lzma   88

```

Note that, although the first string is longer, the second string has a shorter result after being compressed with zlib.
If we make our string only 4 characters, zlib will not compress it unless the next character is the same.

The next character is determined by the seed, as it is used to shuffle the flag.
We know the flag length is 25 because we can subtract our string length from the "none" result.

We can precompute a seed for each index in the flag such that its character will be shuffled to the front, adjacent to our string.

Using this seed, we can enter strings of 4 repeated characters and we know that the correct character is the one that results in the lowest zlib result.

Doing this for each character gives us the full flag.

## Solve script

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host compresstheflag.hackable.software --port 1337
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './path/to/binary'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'compresstheflag.hackable.software'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, level='error')
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

import random

FLAG_PREFIX = 6
FLAG_LEN = 25
seeds = []

for i in range(FLAG_LEN - FLAG_PREFIX - 1):
    seed = 0

    while True:
        placeholder = list("DrgnS{") + list(range(FLAG_LEN - FLAG_PREFIX - 1)) + ['}']
        random.seed(seed)
        random.shuffle(placeholder)
        if placeholder[0] == i:
            seeds.append(seed)
            break
        seed += 1

flag = "DrgnS{"

for seed in seeds:
    letter = ord('A')
    lengths = []

    while letter <= ord('Z'):
        log.info("TRYING " + chr(letter))

        io = start()
        string = chr(letter) * 4
        io.sendlineafter(b'Note: Flag has format DrgnS{[A-Z]+}\n', f"{seed}:{string}".encode())
        io.recvuntil(b'zlib   ')
        length = int(io.recvline().strip())
        io.close()

        letter += 1
        lengths.append(length)

    log.info("zlib lengths: " + str(lengths))

    letter = ord('A') + lengths.index(min(lengths))
    flag += chr(letter)
    log.success(chr(letter))

flag += '}'

log.success(flag)
```

## Flag

`DrgnS{THISISACRIMEIGUESS}`

