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

