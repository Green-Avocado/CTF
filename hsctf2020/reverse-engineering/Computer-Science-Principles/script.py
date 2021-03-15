#!/usr/bin/python

def unshift(encrypted):
    ret = ""
    for i in range(len(encrypted)):
        ret += chr(ord(encrypted[i]) + i)
    return ret

def unshift2(encrypted):
    ret = ""
    for i in range(len(encrypted)):
        ret += chr(ord(encrypted[i]) - len(str(ord(encrypted[i]) - 2)))
    return ret

print(unshift(unshift2("inagzgkpm)Wl&Tg&io")))

