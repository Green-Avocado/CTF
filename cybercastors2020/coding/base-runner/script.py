#!/usr/bin/python
import socket

def binaryToASCII(x):
    return chr(int(x, 2))

def netcat(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))

    done = False
    readingBits = False
    bits = ""
    flag = ""

    while not done:
        data = s.recv(8192).decode()
        if data == "":
            break
        print(data)
        if "<enter>" in data:
            s.sendall("\n".encode())
        else:
            for item in data.split("\n"):
                if "00110110" in item and not readingBits:
                    readingBits = True
                    bits = ""
                if readingBits and "0" not in item and "1" not in item:
                    readingBits = False
                    message = ""
                    for bytesString in bits.split(" "):
                        message += binaryToASCII(bytesString)
                    message += "\n"
                    print(message)
                    s.sendall(message.encode())
                elif readingBits:
                    bits += item
                if "castorsCTF" in item:
                    flag = item.split()[-1]
                    print("\n" + flag)
                    done = True
                    break
    print("Connection closed.")
    s.shutdown(socket.SHUT_WR)
    s.close()
    return flag

flagFileContents = netcat("chals20.cybercastors.com", 14430)

f = open("flag.txt", "w")
f.write(flagFileContents)
f.close()

