#!/usr/bin/python3

import re
import base64

dump = open("dump", "r")

packet = ""

for line in dump:
    line = line.strip().split("   ")
    if len(line) == 2:
        packet += line[1]
    else:
        echocmd = re.search('echo [A-Za-z0-9+/=]+ ', packet)
        if echocmd:
            b64 = echocmd.group(0).split(' ')[1].encode()
            flag = base64.b64decode(b64).decode('utf-8')
            print(flag)

        packet = ""
