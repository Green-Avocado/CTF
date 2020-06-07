#!/usr/bin/python

def unshift(encrypted):
    ret = ""
    for i in range(len(encrypted)):
        ret += chr(ord(encrypted[i]) + i - len(str(ord(encrypted[i]))))
    return ret

print(unshift("inagzgkpm)Wl&Tg&io"))

