# Binary Gauntlet 0

## Description

Author: madStacks

This series of problems has to do with binary protections and how they affect exploiting a very simple program. How far can you make it in the gauntlet?
gauntlet nc -v mercury.picoctf.net 55082
The flag for this challenge does not include the standard picoCTF{} wrapper.

## Challenge

We're given a simple binary, [gauntlet](./gauntlet).

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
void sym.sigsegv_handler(int64_t arg1)
{
    int64_t var_4h;
    
    sym.imp.fprintf(_reloc.stderr, 0x400ac8, obj.flag);
    sym.imp.fflush(_reloc.stderr);
    // WARNING: Subroutine does not return
    sym.imp.exit(1);
}

undefined8 main(undefined8 argc, char **argv)
{
    char **var_90h;
    int64_t var_84h;
    undefined4 var_14h;
    int64_t stream;
    char *format;
    
    var_84h._0_4_ = (undefined4)argc;
    format = (char *)sym.imp.malloc(1000);
    stream = sym.imp.fopen(0x400ace, 0x400acc);
    if (stream == 0) {
        sym.imp.puts(
                    "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server."
                    );
    // WARNING: Subroutine does not return
        sym.imp.exit(0);
    }
    sym.imp.fgets(obj.flag, 0x40, stream);
    sym.imp.signal(0xb, sym.sigsegv_handler);
    var_14h = sym.imp.getegid();
    sym.imp.setresgid(var_14h, var_14h, var_14h, var_14h);
    sym.imp.fgets(format, 1000, _reloc.stdin);
    format[999] = '\0';
    sym.imp.printf(format);
    sym.imp.fflush(_reloc.stdout);
    sym.imp.fgets(format, 1000, _reloc.stdin);
    format[999] = '\0';
    sym.imp.strcpy((int64_t)&var_84h + 4, format, format);
    return 0;
}
```

## Solution

The program first reads the flag from a file into `obj.flag`.

We can see that a handler for segmentation faults has been set up to print this flag to `stderr`.
Therefore, making the program crash will print out the flag.

```asm
[0x004007e0]> pdf @ main
            ; DATA XREF from entry0 @ 0x4007fd
┌ 299: int main (int argc, char **argv);
│           ; var char **var_90h @ rbp-0x90
│           ; var int64_t var_84h @ rbp-0x84
│           ; var char *dest @ rbp-0x80
│           ; var int64_t var_14h @ rbp-0x14
│           ; var file*stream @ rbp-0x10
│           ; var char *format @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x0040090d      55             push rbp
│           0x0040090e      4889e5         mov rbp, rsp
│           0x00400911      4881ec900000.  sub rsp, 0x90
│           0x00400918      89bd7cffffff   mov dword [var_84h], edi    ; argc
│           0x0040091e      4889b570ffff.  mov qword [var_90h], rsi    ; argv

...

│           0x00400a29      4889c7         mov rdi, rax                ; char *dest
│           0x00400a2c      e8effcffff     call sym.imp.strcpy         ; char *strcpy(char *dest, const char *src)
│           0x00400a31      b800000000     mov eax, 0
│           0x00400a36      c9             leave
└           0x00400a37      c3             ret
```

There's an unsafe `strcpy` at the end of the main function into the `*dest` buffer.
This buffer is at `rbp-0x80`, so we can guarantee a crash by writing 0x90 bytes into the buffer, which will replace the return address with something thats likely illegal.

## Flag

`790e8018012932e9d49f9b323123f708`

