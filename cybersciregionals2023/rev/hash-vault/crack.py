#!/usr/bin/env python3

import hashlib
import sys

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_{}/?.>,<!`~[]\|"
md5 = b"\xc2\xea\xf6K\xbf\xc1K\x84d\x85\xef\x9aqw~\xa4"
sha1 = b"\x92-\xd0\xfe\x9b0\x9e\x9d\xa9\x82\xbb{\x8aT\xd8u\x03\x87\xfe\x08"
sha256 = b'\xb7\x1f\x82\x12\xe2\x13Z\x88\xd4\xf8\xcc\xb3\x1d\x04\xd6\x0e\x9f\xd15bR\xc2j\xa5\xf4\x1d\x9c=\x9d[\xfe\xf3'
sha3_512 = b'U\xd6H\xb9\xab\x92d\xcb\x8b\xdc\x94\xeb\xbaY\xd9\xe4\x88\x93\x02\xc7\xb5\xb15\x819\xf5\x84\xd8&\x16o\x99\xe5\x03dL\xf4\x89\xc1\xf5\xa6\x99\xc2\xa4\xf5\x0f\x18l\xd4\xd1\xbbL\xa6M\xe3vk\xcdMb4\xffS*'

for a in alphabet:
    for b in alphabet:
        for c in alphabet:
            for d in alphabet:
                m = hashlib.sha3_512() # change this to the desired hash algo
                s = a + b + c + d
                m.update(s.encode())
                h = m.digest()
                print(s)
                print(h)
                if sha3_512 == h: # change this when changing hashes
                    print(s)
                    sys.exit(0)
