#!/usr/bin/env python3

from PIL import Image
import os

WIDTH = 800
HEIGHT = 400

fingerprint = Image.new('RGBA', (WIDTH, HEIGHT))

sources = []

for file in os.listdir("images/"):
    img = Image.open("images/" + file)
    src = img.load()
    sources.append(src)

pixels_put = 0

for i in range(WIDTH):
    for j in range(HEIGHT):
        for src in sources:
            is_fingerprint = True
            px = src[(i, j)]
            for x in px:
                if x <= 250:
                    is_fingerprint = False
                    break
            if is_fingerprint:
                fingerprint.putpixel((i, j), px)
                pixels_put += 1
                break

print("put {} / {} pixels".format(pixels_put, WIDTH * HEIGHT))
fingerprint.save("fingerprint.png")
