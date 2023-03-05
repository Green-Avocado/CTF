[org 0x0]
[bits 64]

%define FLAG_LEN 0x38

start:

copy_flag:
    std                                        ; set direction flag
    mov rdx, 0                                 ; offset into source buffer
    mov rcx, FLAG_LEN                           ; number of characters to read
    lea rdi, [rel buffer + FLAG_LEN - 1]       ; end of destination buffer
    mov rax, 3                                 ; get_process_data
    int 0x0                                    ; syscall
    cld                                        ; clear direction flag

write_flag:
    lea rsi, [rel buffer]                      ; start of source buffer
    mov byte [rsi + FLAG_LEN], 0               ; append null byte to flag
    mov rax, 1                                 ; write
    int 0x0                                    ; syscall

exit:
    mov rax, 0                                 ; exit
    int 0x0                                    ; syscall

buffer:
