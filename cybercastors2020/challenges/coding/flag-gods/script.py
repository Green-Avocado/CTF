#!/usr/bin/python
import socket

def hamming2(s1, s2):
    assert len(s1) == len(s2)
    return sum(c1 != c2 for c1, c2 in zip(s1, s2))

def processStrings(s1, s2):
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

    return hamming2(binary1,binary2)

def netcat(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))

    done = False
    transmit = ""
    receive = ""
    flag = ""

    while not done:
        data = s.recv(1024).decode()
        if "<enter>" in data:
            s.sendall("\n".encode())
        else:
            for item in data.split("\n"):
                if "calibrated" in item:
                    print(f'{item} \r', end="")
                elif "Transmitted message: " in item:
                    transmit = item[len("Transmitted message: "):]
                elif "Received message: " in item:
                    receive = item[len("Received message: "):]
                elif "Enter hamming distance:" in item:
                    message = str(processStrings(receive, transmit)) + "\n"
                    s.sendall(message.encode())
                elif "castorsCTF" in item:
                    flag = item.split()[-1]
                    print("\n" + flag)
                    done = True
                    break
    print("Connection closed.")
    s.shutdown(socket.SHUT_WR)
    s.close()
    return flag

flagFileContents = netcat("chals20.cybercastors.com", 14431)

f = open("flag.txt", "w")
f.write(flagFileContents)
f.close()

