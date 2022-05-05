from data_arr import data

data[0x1f] = 0x74
data[0x1e] = 0x8dd000
data[0x1d] = 0x950

while data[0x1f] != 0:
    data[0x1f] -= 1
    data[0x1e] -= 0x1000
    data[0x1d] -= 1
    data[(data[0x1e] + data[0x1d]) >> 0xc] ^= data[(data[0x1e] + data[0x1d]) & 0xfff]

from pwn import p32

raw = b''

for i in range(len(data)):
    if i == 0x800:
        raw += p32(0xa6869000)
        continue
    if i > 0x8db:
        break
    raw += p32(data[i])

print(raw)

# patch in binary ninja:
'''
bv.get_data_var_at(0x403c).value = raw
'''
