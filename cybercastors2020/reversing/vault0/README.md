# vault0

## Solution

We're given python code as follows:

```py
def checkpass():
    _input = input("Enter the password: ").encode()
    if _input[0:4].hex() == "63617374":
        if _input[4:9].hex() == "6f72734354":
            if _input[9:14].hex() == "467b723178":
                if _input[14:17].hex() == "54795f":
                    if _input[17:20].hex() == "6d316e":
                        if _input[20:27].hex() == "757433735f6774":
                            if _input[27:35].hex() == "5f73317874795f6d":
                                if _input[35:40].hex() == "316e757433":
                                    if _input[40:].hex() == "737d":
                                        return True

def main():
    global access
    access = checkpass()
    if access:
        print("Yeah...okay. You got it!")
    else:
        print("Lol...try again...")

access = False
main()
```

As we can see, the ```checkpass()``` function verifies the password we enter by encoding it and comparing it to a hexadecimal value.
There has been an attempt to obfuscate the code as the password is checked in chunks.

Fortunately for us, the chunks are all in order, and there are no overlapping chunks.
This means we can simply concatonate all the parts in the order they're presented and convert from hexadecimal to plain-text for our string.

## Script

```py
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
```

## Flag

```castorsCTF{r1xTy_m1nut3s_gt_s1xty_m1nut3s}```

