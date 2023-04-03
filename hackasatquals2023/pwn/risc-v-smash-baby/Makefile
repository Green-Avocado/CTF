.PHONY: default
default: shellcode
	riscv64-linux-gnu-objdump -D -b binary -m riscv:rv32 shellcode

shellcode: shellcode.o
	riscv64-linux-gnu-objcopy -O binary -j .text shellcode.o shellcode

shellcode.o: shellcode.S
	riscv64-linux-gnu-gcc -march=rv32idc -mabi=ilp32d -c shellcode.S -o shellcode.o

.PHONY: clean
clean:
	rm -rf shellcode shellcode.o
