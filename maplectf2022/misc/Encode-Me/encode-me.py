#!/usr/bin/env python3

import base64
import random
import signal
import sys

LEVELS = 1337
INTERVAL = 30

TITLECARD = r"""
  _____                     _        __  __      
 | ____|_ __   ___ ___   __| | ___  |  \/  | ___ 
 |  _| | '_ \ / __/ _ \ / _` |/ _ \ | |\/| |/ _ \
 | |___| | | | (_| (_) | (_| |  __/ | |  | |  __/
 |_____|_| |_|\___\___/ \__,_|\___| |_|  |_|\___|

"""

def encode_bytes(x):
    return x.to_bytes(8, 'little')

def encode_base64(x):
    return base64.b64encode(x.to_bytes(8, 'big'))

def encode_hex(x):
    return hex(x).encode()

def encode_binary(x):
    return bin(x).encode()

encodings = [
        {
            'name': 'bytes (little endian)',
            'function': encode_bytes,
        },
        {
            'name': 'base64',
            'function': encode_base64,
        },
        {
            'name': 'hexadecimal',
            'function': encode_hex,
        },
        {
            'name': 'binary',
            'function': encode_binary,
        },
    ]

def handler(signum, stack):
    print("Timeout: took longer than {} seconds to respond to challenge".format(INTERVAL))
    sys.exit(0)

def challenge():
    signal.alarm(INTERVAL)

    encoding = random.choice(encodings)

    while True:
        message = random.randint(0, 2**64 - 1)
        answer = encoding['function'](message)

        if b'\n' not in answer:
            break

    print("Return {} as {}".format(str(message), encoding['name']))

    print("\nEncoded number: ", end="", flush=True)
    response = sys.stdin.buffer.readline()[:-1]

    if response == answer:
        print("Correct!")
        return True
    else:
        print("Incorrect!")
        print("Expected: {}\nGot: {}".format(answer, response))
        return False

def main():
    signal.signal(signal.SIGALRM, handler)

    print(TITLECARD)
    print("Encode the given unsigned integers as instructed")
    print("Values are big endian unless stated otherwise")
    print("Reach a score of {} to get the flag".format(LEVELS))

    score = 0

    while True:
        print("\n\nScore: {}".format(score))

        if score < LEVELS:
            if not challenge():
                sys.exit(0)
            score += 1
        else:
            break

    print("Congratulations! Here's your flag:")
    flag = open("flag.txt", "r").read()
    print(flag)

if __name__ == "__main__":
    main()
