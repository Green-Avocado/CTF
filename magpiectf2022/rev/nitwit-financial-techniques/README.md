# Nitwit Financial Techniques

## Challenge

We're given a website which displays a randomised image of a flag every time we refresh the page.

We also get the source code used to generate the flags, but not any of the template images used.

The goal is to find a "fingerprint" used to generate the images and email it to a given email address.
If we get the correct fingerprint, we will receive a reply with the flag for the challenge.

## Solution

### Analysing the generator and sample images

Looking at the main loop for generating images, we see that the generator is performing the same operations on the fingerprint three times.
Each time, it uses a different second image, which are the `division,` `overlay`, and `symbol`.

```py
fingerprint = Image.open('fingerprint.png')
division = getFile(dirname, 'division')
divisionLayer = Image.open(division)
overlay = getFile(dirname, 'overlay')
overlayLayer = Image.open(overlay)
symbol = getFile(dirname, 'symbol')
symbolLayer = Image.open(symbol)
divisionPixelMap = divisionLayer.load()
divisionPixelMap = paintLayer(divisionPixelMap)
fingerprint.paste(divisionLayer, (0, 0), divisionLayer)
overlayPixelMap = overlayLayer.load()
overlayPixelMap = paintLayer(overlayPixelMap)
fingerprint.paste(overlayLayer, (0, 0), overlayLayer)
symbolPixelMap = symbolLayer.load()
symbolPixelMap = paintLayer(symbolPixelMap)
fingerprint.paste(symbolLayer, (0, 0), symbolLayer)
```

Note the use of the second image as its own mask.
This means that the alpha of the layer will act as a mask, so that any pixels in the second image with an alpha of 0 will not be copied.

The operation is fairly straightforward.
It gets two random colours, replaces all red pixels with one colour, and all black pixels with another.

```py
def paintLayer(pixelMap):
    colour1 = pickColour()
    colour2 = pickColour()
    for i in range(WIDTH):
        for j in range(HEIGHT):
            if pixelMap[(i, j)] == BLACK:
                pixelMap[(i, j)] = colour1
            else:
                if pixelMap[(i, j)] == RED:
                    pixelMap[(i, j)] = colour2
                    continue
                    continue
        else:
            return pixelMap
```

We can see this reflected in the generated flags, as they are all variations of the same symbols and patterns but with different colours.
In any given image, there are up to 7 different colours.

If we look at a few images, we can see that white is a common background for all images.
We know that all images will share the fingerprint as the background.

Looking closer at the background, we see there is some slight noise in the background.
The white pixels have RGBA values varying within [251, 255].

If we compare these variations between images, the same values appear in the same position.
This must be our fingerprint.

### Reconstucting the fingerprint.

Since the finger print is the same in all positions, we can simply stitch pieces of it together from a collection of sample images.

First, we need to download a number of images that have the pieces needed to construct a whole fingerprint.

For one of the random colours to have all RGBA values in [251, 255] is extremely unlikely and I did not run into any image where this was the case.
However, if one did come across such an image, it would be easier to ignore the sample, as it would have made it more difficult to determine which pixels belonged to the fingerprint.

Once a sufficient set of images has been acquired, one can loop through all the pixels in a new image of the same size, copying pixels from images where the fingerprint exists at that position.
By the end of the process, a complete fingerprint will have been generated which can be emailed to the given email address in exchange for the flag.

### Post-competition note

Before solving the challenge using PIL, I tried using image editting software including Pinta and Gimp.
However, despite the diffs between my images and the sample images passing tests using ImageMagick, none of my attempts were accepted.

In the end, I decided to try using PIL as it was used by the generator.
However, I believe that my earlier submissions should have been accepted, as the generator simply copies RGBA values from the fingerprint file, so identical pixels is all that should be necessary.

The source code released by the organisers for this challenge reveals that submissions were verified by comparing the attachment hash to the hash of the fingerprint.
This is unfortunate for attempts made without the PIL library, as any change to the image metadata would result in a potentially valid solution being rejected.

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
