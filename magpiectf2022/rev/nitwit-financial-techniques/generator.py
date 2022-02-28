# decompyle3 version 3.7.6
# Python bytecode 3.8 (3413)
# Decompiled from: Python 3.8.10 (default, Sep 28 2021, 16:10:42) 
# [GCC 9.3.0]
# Embedded file name: generator.py
from PIL import Image
import os
from random import choice, choices
import uuid, sys
WIDTH = 800
HEIGHT = 400
BLACK = (0, 0, 0, 255)
RED = (255, 0, 0, 255)

def getFile(dirname, folder):
    while True:
        randomFile = choice(os.listdir(os.path.join(dirname, folder)))
        if randomFile.endswith('.png'):
            return os.path.join(dirname, folder, randomFile)


def pickColour():
    colour = choices((range(256)), k=3)
    colour.append(255)
    colour = tuple(colour)
    return colour


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


if getattr(sys, 'frozen', False):
    dirname = os.path.dirname(sys.executable)
elif __file__:
    dirname = os.path.dirname(os.path.abspath(__file__))
for i in range(2000):
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
    fileName = uuid.uuid4().hex
    fileName = './flags/' + fileName + '.png'
    fingerprint.save(fileName)