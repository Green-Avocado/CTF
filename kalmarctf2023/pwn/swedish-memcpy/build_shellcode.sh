nasm -f bin shellcode.s -o shellcode.bin; objdump -D -b binary -mi386 -Maddr16,data16,intel shellcode.bin
