# Arithmetics

A user connected to a program through TCP, using netcat of the python ```socket``` module.
The user would be prompted with a series of questions involving two operands ranging from 1-9, and an operation from the following list: addition, subtraction, multiplication, integer division.
These could be given as digits and symbols (e.g. 1 + 2), or they could be replaced with words (e.g. one plus two).
Though these calculations were simple and could be done by a human, there was a very limited amount of time to answer these questions, which basically required the use of a script.

## Solution

I created a function to connect to the program for receiving and sending data.
First, it would receive data and send a newline character when it detected ```<enter>```, which would allow the trial to begin.
A while loop would execute until a flag was detected, in which case it would exit and return the flag.

```py
def netcat(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))

    done = False
    flag = ""

    while not done:
        data = s.recv(1024).decode()
        print(data)
        if "<enter>" in data:
            s.sendall("\n".encode())

    ...

    print("Connection closed.")
    s.shutdown(socket.SHUT_WR)
    s.close()
    return flag
```

If it did not contain ```<enter>```, it was assumed that the trial had begun, so the data was separated by line and each line was parsed.
If a line contained ```What is ```, I knew it would be a question and I could parse this line further.
The questions had a pretty standard format, so I split the line containing the question into a list, using spaces as the delimiter.

```py
for item in data.split("\n"):
    if "What is " in item:
        arr = item.split()
```

To determine what the question was asking, I first passed the numbers and operation to the ```toNum()``` and ```toOp()``` functions, respectively.

```py
a = toNum(arr[2])
b = toNum(arr[4])
op = toOp(arr[3])
```

The ```toNum()``` function contained a dictionary matching each possible word with the numeric value.
It would try to set the value of the return variable to a corresponding integer using this dictionary.
If this failed, we could be confident that it was already a digit, and all that was needed was to parse the string as an integer.

```py
def toNum(x):
    num_map = {
        "one":1,
        "two":2,
        "three":3,
        "four":4,
        "five":5,
        "six":6,
        "seven":7,
        "eight":8,
        "nine":9,
    }

    try:
        y = num_map[x]
    except:
        y = int(x)

    return y
```

The ```toOp()``` function checked for known keywords for operations, and would set the operation to the correct symbol if found.
If none of these matched, we could be confident that it was already a symbol and return the parameter unchanged.

```py
def toOp(x):
    if "multiplied" in x:
        x = "*"
    elif "divided" in x:
        x = "//"
    elif "plus" in x:
        x = "+"
    elif "minus" in x:
        x = "-"

    return x
```

Using the parsed data, we could use built-in python functions and operations to do the calculation, convert it to a string, encode it, and send it to the server.

```py
res = ""
if "*" in op:
    res = str(a * b)
elif "/" in op:
    res = str(math.floor(a / b))
elif "+" in op:
    res = str(a + b)
elif "-" in op:
    res = str(a - b)
res += "\n"
print(res)
s.sendall(res.encode())
```

## Script

```py
#!/usr/bin/python
import socket
import math

def toNum(x):
    num_map = {
        "one":1,
        "two":2,
        "three":3,
        "four":4,
        "five":5,
        "six":6,
        "seven":7,
        "eight":8,
        "nine":9,
    }

    try:
        y = num_map[x]
    except:
        y = int(x)

    return y

def toOp(x):
    if "multiplied" in x:
        x = "*"
    elif "divided" in x:
        x = "//"
    elif "plus" in x:
        x = "+"
    elif "minus" in x:
        x = "-"

    return x

def netcat(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))

    done = False
    flag = ""

    while not done:
        data = s.recv(1024).decode()
        print(data)
        if "<enter>" in data:
            s.sendall("\n".encode())
        else:
            for item in data.split("\n"):
                if "What is " in item:
                    arr = item.split()
                    a = toNum(arr[2])
                    b = toNum(arr[4])
                    op = toOp(arr[3])
                    res = ""
                    if "*" in op:
                        res = str(a * b)
                    elif "/" in op:
                        res = str(math.floor(a / b))
                    elif "+" in op:
                        res = str(a + b)
                    elif "-" in op:
                        res = str(a - b)
                    res += "\n"
                    print(res)
                    s.sendall(res.encode())
                elif "castorsCTF" in item:
                    flag = item.split()[-1]
                    print("\n" + flag)
                    done = True
                    break
    print("Connection closed.")
    s.shutdown(socket.SHUT_WR)
    s.close()
    return flag

flagFileContents = netcat("chals20.cybercastors.com", 14429)

f = open("flag.txt", "w")
f.write(flagFileContents)
f.close()
```

## Flag

```castorsCTF(n00b_pyth0n_4r17hm3t1c5}```

