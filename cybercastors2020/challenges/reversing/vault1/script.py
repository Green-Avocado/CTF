#!/usr/bin/python
import base64

def xor(s1,s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

target = b'ExMcGQAABzohNQ0TRQwtPidYAS8gXg4kAkcYISwOUQYS'
key = "promortyusvatofacidpromortyusvato"

target = base64.b64decode(target, altchars=None)
decoded = target.decode()

flag = xor(key, decoded)

print(flag)

f = open("flag.txt", "w")
f.write(flag)
f.close()

