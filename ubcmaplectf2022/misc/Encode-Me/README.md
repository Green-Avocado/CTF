# Encode Me

## Challenge

Connecting to the server prompts us with the following banner message:

```

  _____                     _        __  __      
 | ____|_ __   ___ ___   __| | ___  |  \/  | ___ 
 |  _| | '_ \ / __/ _ \ / _` |/ _ \ | |\/| |/ _ \
 | |___| | | | (_| (_) | (_| |  __/ | |  | |  __/
 |_____|_| |_|\___\___/ \__,_|\___| |_|  |_|\___|


Encode the given unsigned integers as instructed
Values are big endian unless stated otherwise
Reach a score of 1337 to get the flag
```

We then get our current score printed as well as a number an a encoding format, such as the following:

```
Return 10787159927914914065 as binary
```

```
Return 2270043206429590058 as base64
```

```
Return 6644526087115133049 as hexadecimal
```

```
Return 16998562070352082986 as bytes (little endian)
```

Encoding the message successfully will increase our score and give us another randomized number and format.

If we get a any prompt wrong, the connection will be closed and we will have to restart from 0.

If we reach a score of 1337, the server will print the flag for us.

## Solution

The intended solution is to use a script to encode these prompts.
It takes around 3 minutes to solve it using a script and is not practical to solve by hand.

A variety of scripting languages and libraries are available.
The hope for this challenge was that:

- Players would be able to send raw bytes and other forms of data to a service,
which would be useful especially in binary exploit challenges.
- Players would discover libraries such as [pwntools](https://github.com/Gallopsled/pwntools),
which would be very useful in binary exploit challenges.

The solution described in this writeup uses pwntools.

We can open a connection using

```py
io = connect(host, port)
```

We can ignore everything the server sends until the start of a challenge using

```py
io.recvuntil(b"Return ")
```

Next, we can read the integer and encoding format with

```py
number = int(io.recvuntil(b" as ", drop=True))
encoding = io.recvuntil(b"\n", drop=True).decode()
```

We can now pass these numbers to the appropriate encoding function.

For these functions, we can simply look at the source code for the challenge,
which must also encode these numbers to verify our input.

```py
def encode_bytes(x):
    return x.to_bytes(8, 'little')

def encode_base64(x):
    return base64.b64encode(x.to_bytes(8, 'big'))

def encode_hex(x):
    return hex(x).encode()

def encode_binary(x):
    return bin(x).encode()
```

This can be copied directly into our solve script.
We can now set up a dictionary for these scripts.

```py
encodings = {
        'bytes (little endian)': encode_bytes,
        'base64': encode_base64,
        'hexadecimal': encode_hex,
        'binary': encode_binary,
    }
```

And finally, we pass the number through the function and send the result to the server.

```py
io.sendlineafter(b"Encoded number: ", encodings[encoding](number))
```

We can loop these above steps 1337 times until we get the flag.

## Script

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1421 encode-me.py
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'encode-me.py'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1421)

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

def encode_bytes(x):
    return x.to_bytes(8, 'little')

def encode_base64(x):
    return base64.b64encode(x.to_bytes(8, 'big'))

def encode_hex(x):
    return hex(x).encode()

def encode_binary(x):
    return bin(x).encode()

encodings = {
        'bytes (little endian)': encode_bytes,
        'base64': encode_base64,
        'hexadecimal': encode_hex,
        'binary': encode_binary,
    }

io = start()

for i in range(1337):
    print(io.recvuntil(b"Return "))

    number = int(io.recvuntil(b" as ", drop=True))
    encoding = io.recvuntil(b"\n", drop=True).decode()

    io.sendlineafter(b"Encoded number: ", encodings[encoding](number))

io.interactive()
```

## Flag

```
maple{d1d_y0u_u5e_pwnt00l5?}
```
