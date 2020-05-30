#!/usr/bin/python
import socket

def netcat(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))

    hasVPN = False
    selling = False
    working = True
    done = False
    flag = ""

    while not done:
        data = s.recv(1024)
        for item in data.decode().split("\n"):
            if "Your money: " in item and not "Here's" in item:
                print(f'{item} \r', end="")
                break
        if "Your money: 6000" in data.decode():
            working = False
        if "Choice: " in data.decode():
            if not working:
                message = "5\n"
            else:
                if hasVPN and selling:
                    message = "0\n"
                    selling = False
                elif hasVPN and not selling:
                    message = "1\n"
                    selling = True
                else:
                    message = "6\n"
                    hasVPN = True
            s.sendall(message.encode())
        if "castorsCTF" in data.decode():
            print("Flag:", data.decode())
            for item in data.decode().split("\n"):
                if "castorsCTF" in item:
                    flag = item
                    break
            done = True
    print("Connection closed.")
    s.shutdown(socket.SHUT_WR)
    s.close()
    return flag

flagFileContents = netcat("chals20.cybercastors.com", 14432)

f = open("flag.txt", "w")
f.write(flagFileContents)
f.close()

