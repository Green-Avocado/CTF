disasm = {}

def process_ins(ins, offset):
    op = ins >> 0x18
    arg1 = (ins >> 0xc) & 0xfff
    arg2 = ins & 0xfff
    text = None
    target = None
    match op:
        case 0x00:
            text = 'halt'
        case 0xd6:
            text = f'mov [{hex(arg1)}], [{hex(arg2)}]'
        case 0xd8:
            text = f'mov [{hex(arg1)}], {hex(arg2)}'
        case 0x16:
            text = f'add [{hex(arg1)}], [{hex(arg2)}]'
        case 0x17:
            text = f'sub [{hex(arg1)}], [{hex(arg2)}]'
        case 0x18:
            text = f'xor [{hex(arg1)}], [{hex(arg2)}]'
        case 0x69:
            target = arg2
            if target > 0x7ff:
                target -= 0x1000
            target += offset
            text = f'brz [{hex(arg1)}] {hex(target)}'
        case 0xa6:
            target = arg1 + 1
            text = f'jmp {hex(target)}'
        case 0xf6:
            text = f'put [{hex(arg1)}]'
        case 0xf7:
            text = f'get {hex(arg1)}'
        case _:
            text = 'nop'

    if target:
        if target not in disasm:
            disasm[target] = {}
            disasm[target]['text'] = ''
            disasm[target]['xref'] = []
        disasm[target]['xref'].append(offset)
    if text:
        if offset not in disasm:
            disasm[offset] = {}
            disasm[offset]['text'] = ''
            disasm[offset]['xref'] = []
        disasm[offset]['text'] = text

from data_arr import data

data[0x1f] = 0x74
data[0x1e] = 0x8dd000
data[0x1d] = 0x950

while data[0x1f] != 0:
    data[0x1f] -= 1
    data[0x1e] -= 0x1000
    data[0x1d] -= 1
    data[(data[0x1e] + data[0x1d]) >> 0xc] ^= data[(data[0x1e] + data[0x1d]) & 0xfff]

for i in range(len(data)):
    process_ins(data[i], i)

disasm = dict(sorted(disasm.items()))

for i in disasm:
    if i < 0x869:
        continue
    if i > 0x8db:
        break
    addr = 0x4038 + (i * 4)
    fulltext = disasm[i]['text']
    if len(disasm[i]['xref']) > 0:
        fulltext = fulltext.ljust(0x20, ' ') + 'XREFS: ' + str([hex(x) for x in disasm[i]['xref']])
    print(hex(i), f'{data[i]:x}', fulltext)
