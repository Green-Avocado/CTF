#!/usr/bin/python
import urllib.request

URL = "https://castorsctf20.ctfd.io/readme"

page = urllib.request.urlopen(URL)
text = page.read().decode()

text = text[text.find("castorsCTF{") + 1:]
flag = text[text.find("castorsCTF{"):]
flag = flag[:flag.find("}") + 1]

print(flag)

f = open("flag.txt", "w")
f.write(flag)
f.close()

