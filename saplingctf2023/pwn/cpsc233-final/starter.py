from pwn import *

exe = ELF("cpsc233_final")

context.binary = exe
# context.log_level = 'DEBUG'

LOCAL = False

if args.LOCAL or LOCAL:
    io = process([exe.path])
else:
    io = remote("rua_host_goes_here", 1337)

your_asm_code_here = '''
ret
'''

shellcode = asm(your_asm_code_here)

log.info("Shellcode: ")
print(your_asm_code_here)
log.info("Assembled code: ")
print(shellcode.hex().upper())

log.info("sending your function to autograder")

io.sendlineafter(b"here: ",shellcode.hex().encode())
print(io.recvall().decode())
io.close()