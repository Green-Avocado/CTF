import socketserver
from os import urandom
from random import seed, randint
from secret import FLAG

BANNER = b"""
 ______  ______ ______  __      __  __       __    __  ______  ______  __  __  ______ ______  
/\  ___\/\__  _/\  __ \/\ \    /\ \/ /      /\ "-./  \/\  __ \/\  == \/\ \/ / /\  ___/\__  _\ 
\ \___  \/_/\ \\\ \  __ \ \ \___\ \  _"-.    \ \ \-./\ \ \  __ \ \  __<\ \  _"-\ \  __\/_/\ \/ 
 \/\_____\ \ \_\\\ \_\ \_\ \_____\ \_\ \_\    \ \_\ \ \_\ \_\ \_\ \_\ \_\ \_\ \_\ \_____\\\ \_\ 
  \/_____/  \/_/ \/_/\/_/\/_____/\/_/\/_/     \/_/  \/_/\/_/\/_/\/_/ /_/\/_/\/_/\/_____/ \/_/ 
                                                                                              """
MESSAGE = b"""
Breaking news!
The algorithm that generates turnip prices has been data mined.
All prices for the week are generated on Monday at midnight.
Understand how the algorithm works and predict prizes for
the next 20 weeks to become the Ultimate Turnip Prophet!\n
"""

sbox = [92, 74, 18, 190, 162, 125, 45, 159, 217, 153, 167, 179, 221, 151, 140, 100, 227, 83, 8, 4, 80, 75, 107, 85, 104, 216, 53, 90, 136, 133, 40, 20, 94, 32, 237, 103, 29, 175, 127, 172, 79, 5, 13, 177, 123, 128, 99, 203, 0, 198, 67, 117, 61, 152, 207, 220, 9, 232, 229, 120, 48, 246, 238, 210, 143, 7, 33, 87, 165, 111, 97, 135, 240, 113, 149, 105, 193, 130, 254, 234, 6, 76, 63, 19, 3, 206, 108, 251, 54, 102, 235, 126, 219, 228, 141, 72, 114, 161, 110, 252, 241, 231, 21, 226, 22, 194, 197, 145, 39, 192, 95, 245, 89, 91, 81, 189, 171, 122, 243, 225, 191, 78, 139, 148, 242, 43, 168, 38, 42, 112, 184, 37, 68, 244, 223, 124, 218, 101, 214, 58, 213, 34, 204, 66, 201, 180, 64, 144, 147, 255, 202, 199, 47, 196, 36, 188, 169, 186, 1, 224, 166, 10, 170, 195, 25, 71, 215, 52, 15, 142, 93, 178, 174, 182, 131, 248, 26, 14, 163, 11, 236, 205, 27, 119, 82, 70, 35, 23, 88, 154, 222, 239, 209, 208, 41, 212, 84, 176, 2, 134, 230, 51, 211, 106, 155, 185, 253, 247, 158, 56, 73, 118, 187, 250, 160, 55, 57, 16, 17, 157, 62, 65, 31, 181, 164, 121, 156, 77, 132, 200, 138, 69, 60, 50, 183, 59, 116, 28, 96, 115, 46, 24, 44, 98, 233, 137, 109, 49, 30, 173, 146, 150, 129, 12, 86, 249]
p = [8, 6, 5, 11, 14, 7, 4, 0, 9, 1, 13, 10, 2, 3, 15, 12]
round = 8

def pad(s):
    if len(s) % 16 == 0:
        return s
    else:
        pad_b = 16 - len(s) % 16
        return s + bytes([pad_b]) * pad_b

def repeated_xor(p, k):
    return bytearray([p[i] ^ k[i] for i in range(len(p))])

def group(s):
    return [s[i * 16: (i + 1) * 16] for i in range(len(s) // 16)]

def hash(data):
    state = bytearray([165, 68, 114, 228, 151, 146, 106, 238, 198, 241, 198, 122, 46, 148, 3, 38])
    data = group(pad(data))
    for roundkey in data:
        for _ in range(round):
            state = repeated_xor(state, roundkey)
            for i in range(len(state)):
                state[i] = sbox[state[i]]
            temp = bytearray(16)
            for i in range(len(state)):
                temp[p[i]] = state[i]
            state = temp
    return state.hex()

def gen_price():
    r = randint(1, 100)
    if   r >= 99: price = randint(500, 600)
    elif r >= 95: price = randint(450, 500)
    elif r >= 90: price = randint(400, 450)
    elif r >= 85: price = randint(350, 400)
    elif r >= 80: price = randint(300, 350)
    elif r >= 75: price = randint(250, 300)
    elif r >=  0: price = randint( 20, 250)
    return price

def gen_hashes_and_prices():
    d = {"mon": {"am": 0, "pm": 0},"tue": {"am": 0, "pm": 0},"wed": {"am": 0, "pm": 0},"thu": {"am": 0, "pm": 0},"fri": {"am": 0, "pm": 0},"sat": {"am": 0, "pm": 0}}
    secret = bytearray(urandom(16))
    seed(int.from_bytes(secret, 'big'))
    hashes = []
    highest = ('day-time', 0)
    for day in d.keys():
        for time in d[day].keys():
            price = d[day][time] = gen_price()
            hashes.append(hash(secret + "-".join([day, time, str(price)]).encode()))
            if price > highest[1]:
                highest = ("-".join([day, time]), price)
    return secret.hex(), " ".join(hashes), d, highest

def disp_prices(req, d, s):
    req.sendall(f"\nThe secret was {s}.\n".encode())
    for day in d.keys():
        for time in d[day].keys():
            req.sendall(f"{day.capitalize()} {time.upper()}: {d[day][time]}\n".encode())

def challenge(req):
    for n in range(20):
        secret, hashes, prices, highest = gen_hashes_and_prices()
        req.sendall(f"Price commitments for the week: {hashes}\n\n".encode())
        req.sendall(f"Monday AM Price: {prices['mon']['am']}\n".encode())
        req.sendall(f"(Week {n+1}) Enter day-time of highest price for the week: ".encode())
        inp = req.recv(256).strip().decode().lower()
        if inp != highest[0]:
            disp_prices(req, prices, secret)
            req.sendall(b"Try again next week.\n")
            exit(0)
        req.sendall(b'You got it!\n')
    else:
        req.sendall(f"Even Tom Nook is impressed. Here's your flag: {FLAG.decode()}".encode())
        exit(0)

class TaskHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(BANNER)
        self.request.sendall(MESSAGE)
        challenge(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 8080), TaskHandler)
    server.serve_forever()