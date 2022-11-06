# Puzzle Vault

## Challenge

We're given a password-checker JavaScript file.

Whitespace formatting has been remove from the file, and it has been obfuscated to hide some variable
names.

## Solution

The JavaScript can first be beautified with an online tool to make it more readable.

We then see the next layer of obfuscation, which has changed some variable names and replaced the
standard method call notation with dictionary accesses.

This style of obfuscation is similar to the one I encountered when [reversing a malicious JavaScript
file](https://github.com/Green-Avocado/bbystealer-malware-analysis), but to a lesser degree.

We can easily figure out which variable is our password as it is the one read from the user.
There are also a few other variables that can be renamed to be more easily recognizable when reverse
engineering.
These can easily be updated in the file using a find-and-replace tool.

From there, we can manually analyze the checks on our input.
Some are simply checking that a character or character code at a certain index equals the specified
value.
Others check if two characters at different indices are equal.
These characters or relations can be noted to slowly reconstruct the password, starting with the
simplest ones which simply check that one character equals a certain value.

For more complicated examples involving math or complex operations, it can often help to extract
a piece of JavaScript and run it to determine what value it is expecting.
For example, consider the following for loop:

```js
nopass = 'No,\x20this\x20is\x20not\x20the\x20password';

...

const _0x1a21fd = [0x20, 0x1d, 0x74, 0x6, 0x6, 0x7, 0x76];
for (i = 0x0; i < _0x1a21fd['length']; i++) {
    if (String['fromCharCode'](_0x1a21fd[i] ^ nopass['charCodeAt'](0x9 + i)) != _0x2fa26d[0xe + i]) {
        bad_password();
        return;
    }
}
```

To determine what characters it expects, we can modify the loop as follows:

```js
nopass = 'No,\x20this\x20is\x20not\x20the\x20password';
const array = [0x20, 0x1d, 0x74, 0x6, 0x6, 0x7, 0x76];
for (i = 0x0; i < array['length']; i++) {
    console.log(String['fromCharCode'](array[i] ^ nopass['charCodeAt'](0x9 + i)), 0xe + i)
}
```

Now, running this gives us the following output:

```
I 14
n 15
T 16
h 17
i 18
s 19
V 20
```

The letters in the left column are the ones that the original loop was comparing for.
The numbers in the right column are the indices in our password where these letters would have been
checked.
We can use this information in our reconstruction of the original password.

Working through the rest of the checks, we find that the password is:

```
ThereIsNoFaultInThisVault
```

We can send this value to the server, which responds with:

```
You are accessing the Puzzle Vault

What is the password?: ThereIsNoFaultInThisVault

Correct! Here are the vault contents:

Encryption key: 12ae03185e820e1e29fc00d68c12714c
```

giving us the final answer to submit for this challenge.
