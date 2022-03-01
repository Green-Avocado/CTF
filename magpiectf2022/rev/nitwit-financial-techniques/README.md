# Nitwit Financial Techniques

## Challenge

We're given a website which displays a randomised image of a flag every time we refresh the page.

We also get the source code used to generate the flags, but not any of the template images used.

The goal is to find a "fingerprint" used to generate the images and email it to a given email address.
If we get the correct fingerprint, we will receive a reply with the flag for the challenge.

## Solution

## Script

```py
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
```

## Flag

```
magpie{8uy_5tUp1d_t3CH_m4K3_5TuP1d_m0N3y}
```
