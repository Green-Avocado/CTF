from data_arr import data

data[0x0] = 0x0
data[0x1] = 0x1
data[0x3] = 0x1ff
data[0x10] = 0x0
data[0x11] = 0x0
data[0x12] = 0x0
data[0x13] = 0x0
data[0x14] = 0x0
data[0x15] = 0x0
data[0x16] = 0x0
data[0x17] = 0x0
data[0x18] = 0x0
data[0x19] = 0x0
data[0x1a] = 0x0
data[0x1b] = 0x0
data[0x1c] = 0x0
data[0x1d] = 0x0
data[0x1e] = 0x0
data[0x1f] = 0x0

data[0x1a] = 0xfff
while data[0x1a] != 0:
    data[0x1a] -= 1

    data[0x19] = 0xfff
    while data[0x19] != 0:
        data[0x19] -= 1

        data[0x18] = 0xfff
        while data[0x18] != 0:
            data[0x18] -= 1

            data[0x17] = 0xfff
            while data[0x17] != 0:
                data[0x17] -= 1

                data[0x1f] = 0x74
                data[0x1e] = 0x8dd
                data[0x1d] = 0x950
                data[0x1b] = 0x1
                data[0x10] = 0x10

                data[0x11] += 0x8dd0

                data[0x11] *= 0x100

                data[0x1e] = data[0x11]

                data[0x11] = 0x10

                data[0x11] *= 0x100

                data[0x1b] = data[0x11]

                data[0x11] = 0
                data[0x1c] = 0x10
                data[0x10] = 0x10

                while data[0x1f] != 0:
                    data[0x1f] -= 1
                    data[0x1e] -= data[0x1b]
                    data[0x1d] -= 1
                    print(hex(data[0x1e]), hex(data[0x1d]))
                    print(hex((data[0x1e] + data[0x1d]) >> 0xc), hex(data[(data[0x1e] + data[0x1d]) >> 0xc]))
                    print()
                    data[(data[0x1e] + data[0x1d]) >> 0xc] ^= data[(data[0x1e] + data[0x1d]) & 0xfff]