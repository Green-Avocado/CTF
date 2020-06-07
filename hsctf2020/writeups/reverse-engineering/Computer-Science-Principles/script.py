#!/usr/bin/python

def unshift(encrypted, shift):
    ret = ""
    for i in range(len(encrypted)):
        ret += chr(ord(encrypted[i]) + i - shift)
    return ret

print(unshift("inagzgkpm)Wl&Tg&io", 2))
print(unshift("inagzgkpm)Wl&Tg&io", 3))

