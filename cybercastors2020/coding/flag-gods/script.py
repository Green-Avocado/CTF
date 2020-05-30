#!/usr/bin/python
import binascii

def hamming2(s1, s2):
    assert len(s1) == len(s2)
    return sum(c1 != c2 for c1, c2 in zip(s1, s2))

s1 = "0aca309d9fb3ce9e1eba9c9c5d8f1086d6d4899e0fadefcefe879ecd8d46df12984f11c3d96691"
s2 = "The clueless boy jumps a puppy merrily."

hex2bin_map = {
   "0":"0000",
   "1":"0001",
   "2":"0010",
   "3":"0011",
   "4":"0100",
   "5":"0101",
   "6":"0110",
   "7":"0111",
   "8":"1000",
   "9":"1001",
   "a":"1010",
   "b":"1011",
   "c":"1100",
   "d":"1101",
   "e":"1110",
   "f":"1111",
}
binary1 = ''.join(hex2bin_map[i] for i in s1)
binary2 = ''.join(format(ord(i),'b').zfill(8) for i in s2)

print(hamming2(binary1,binary2))

