#!/usr/bin/python
import binascii

with open('two-paths.png', 'rb') as f:
    lines = f.read().splitlines()
    last_line = lines[-1]
    n = int(last_line.decode("utf-8").replace(" ",""), 2)
    print(binascii.unhexlify('%x' % n).decode("utf-8"))

