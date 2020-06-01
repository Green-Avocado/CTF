#!/usr/bin/python
def flagadd(flag, hexpart):
    flag += bytearray.fromhex(hexpart).decode()
    return flag

flag = ""
flag = flagadd(flag, "63617374");
flag = flagadd(flag, "6f72734354");
flag = flagadd(flag, "467b723178");
flag = flagadd(flag, "54795f");
flag = flagadd(flag, "6d316e");
flag = flagadd(flag, "757433735f6774");
flag = flagadd(flag, "5f73317874795f6d");
flag = flagadd(flag, "316e757433");
flag = flagadd(flag, "737d");

print(flag);

f = open("flag.txt", "w")
f.write(flag)
f.close()

