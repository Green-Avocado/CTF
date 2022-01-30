#!/usr/bin/env python3

import base64
import random
import signal
import sys

LEVELS = 1337
INTERVAL = 30

TITLECARD = r"""
  ____                     _        __  __      
 |  _ \  ___  ___ ___   __| | ___  |  \/  | ___ 
 | | | |/ _ \/ __/ _ \ / _` |/ _ \ | |\/| |/ _ \
 | |_| |  __/ (_| (_) | (_| |  __/ | |  | |  __/
 |____/ \___|\___\___/ \__,_|\___| |_|  |_|\___|

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

    answer = random.randint(0, 2**64 - 1)
    message = encoding['function'](answer)

    print("\n-----BEGIN {} ENCODED MESSAGE-----".format(encoding['name'].upper()), flush=True)
    sys.stdout.buffer.write(message)
    print("\n-----END {} ENCODED MESSAGE-----".format(encoding['name'].upper()))

    response = input("\nDecoded number: ")

    try:
        response = int(response)
    except:
        print("Error: not a base 10 integer")
        return False

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
    print("Decode the given values as unsigned integers")
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
