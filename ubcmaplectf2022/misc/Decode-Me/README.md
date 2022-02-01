# Decode Me

## Challenge

Connecting to the server prompts us with the following banner message:

```

  ____                     _        __  __      
 |  _ \  ___  ___ ___   __| | ___  |  \/  | ___ 
 | | | |/ _ \/ __/ _ \ / _` |/ _ \ | |\/| |/ _ \
 | |_| |  __/ (_| (_) | (_| |  __/ | |  | |  __/
 |____/ \___|\___\___/ \__,_|\___| |_|  |_|\___|


Decode the given values as unsigned integers
Values are big endian unless stated otherwise
Reach a score of 1337 to get the flag
```

We then get our current score printed as well as an encoded message, such as the following:

```
-----BEGIN BASE64 ENCODED MESSAGE-----
cO+5NfocJLY=
-----END BASE64 ENCODED MESSAGE-----
```

```
-----BEGIN BYTES (LITTLE ENDIAN) ENCODED MESSAGE-----
�խ��TI�
-----END BYTES (LITTLE ENDIAN) ENCODED MESSAGE-----
```

```
-----BEGIN HEXADECIMAL ENCODED MESSAGE-----
0x49bfd66a1d2c4b15
-----END HEXADECIMAL ENCODED MESSAGE-----
```

```
-----BEGIN BINARY ENCODED MESSAGE-----
0b1011111100100110000110100011101001010011101001101111000010000110
-----END BINARY ENCODED MESSAGE-----
```

Decoding a message successfully will increase our score and give us another randomized message.

If we get a any prompt wrong, the connection will be closed and we will have to restart from 0.

If we reach a score of 1337, the server will print the flag for us.

## Solution

The intended solution is to use a script to decode these prompts.
It takes around 3 minutes to solve it using a script and is not practical to solve by hand.

A variety of scripting languages and libraries are available.
The hope for this challenge was that:

- Players would be able to decode raw bytes and other forms of encoded data,
which would be useful especially in binary exploit challenges.
- Players would discover libraries such as [pwntools](https://github.com/Gallopsled/pwntools),
which would be very useful in binary exploit challenges.

The solution described in this writeup uses pwntools.

We can open a connection using

```py
io = connect(host, port)
```

We can receive until start of the message using

```py
io.recvuntil(b"-----BEGIN ")
```

Now, the next words will indicate what format was used to encode the message.
We can get this format using

```py
encoding = io.recvuntil(b" ENCODED MESSAGE-----\n", drop=True).decode()
```

This will store the format as a string, for example `encoding = "BINARY"`.

Next, we store the encoded message and pass it to our decoding functions.

```py
message = io.recvuntil(b"\n-----END", drop=True)

io.sendlineafter(b"Decoded number: ", str(decode_funcs[encoding](message)).encode())
```

For our decode functions, we can reverse the encode functions found in the source.

In some cases, we simple parse an integer with a different radix.

```py
def decode_hex(x):
    return int(x.decode(), 0)

def decode_binary(x):
    return int(x.decode(), 0)
```

Base64 is more complicated.
We have to convert to bytes first, which can be done using the inverse of the function that the server uses.
Once we have the message in bytes, we can decode it as a big-endian integer.

```py
def decode_base64(x):
    return int.from_bytes(base64.b64decode(x.decode()), "big")
```

Little-endian bytes is where pwntools was especially useful.
Because all messages were 8 bytes long, we could use the `u64` function to unpack a 64-bit integer.

```py
def decode_bytes(x):
    return u64(x)
```

Now that we have functions to decode all the possible formats, we can loop through all 1337 rounds until we get the flag.

## Script

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1420 decode-me.py
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'decode-me.py'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1420)

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

import base64

def decode_bytes(x):
    return u64(x)

def decode_base64(x):
    return int.from_bytes(base64.b64decode(x.decode()), "big")

def decode_hex(x):
    return int(x.decode(), 0)

def decode_binary(x):
    return int(x.decode(), 0)

decode_funcs = {
        'BYTES (LITTLE ENDIAN)': decode_bytes,
        'BASE64': decode_base64,
        'HEXADECIMAL': decode_hex,
        'BINARY': decode_binary,
    }

io = start()

for i in range(1337):
    io.recvuntil(b"-----BEGIN ")

    encoding = io.recvuntil(b" ENCODED MESSAGE-----\n", drop=True).decode()
    message = io.recvuntil(b"\n-----END", drop=True)

    io.sendlineafter(b"Decoded number: ", str(decode_funcs[encoding](message)).encode())

io.interactive()
```

## Flag

```
maple{15_th15_crypt0??}
```
