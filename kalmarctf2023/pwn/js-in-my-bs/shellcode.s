[org 0x7c00]
[bits 16]

start:
    mov ah, 0x2                ; read sectors from drive
    nop
    mov al, 1                  ; sectors to read
    nop
    mov ch, 0                  ; cylinder idx
    nop
    mov dh, 0                  ; head idx
    nop
    mov cl, 2                  ; sector idx
    nop
    mov dl, 0x80               ; disk idx
    nop
    mov bx, 0x7e00             ; target pointer
    int 0x13                   ; interrupt
    mov dx, 0x3f8              ; serial out
    mov si, bx                 ; source buffer (start of flag)

loop:
    lodsb                      ; load byte from si into al, advance si
    out dx, al                 ; send al to serial out
    jmp loop                   ; repeat
