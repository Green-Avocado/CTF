# Hash Vault

## Challenge

We're given a password-checker binary.

If we enter the correct password, the binary will read a file and output its results.

The password check is hardcoded, so we can determine the password locally, then use it on the server.
The server has the targetted file.

## Solution

By reverse engineering the program, we can see that the password must have a length of 20 characters.

We can also see that:

- The first 4 characters are hashed using MD5 and the result is compared to a hard-coded hash.
- The second 4 characters are hashed using SHA1 and the result is compared to a hard-coded hash.
- The third 4 characters are hashed using SHA256 and the result is compared to a hard-coded hash.
- The fourth 4 characters are hashed using CRC32 and the result is compared to a hard-coded hash.
- The fifth 4 characters are hashed using SHA3\_256 and the result is compared to a hard-coded hash.

Being only 4 characters each, we can bruteforce each of these parts individually.
We hash strings of 4 printable characters at a time and compare the hash to those extracted from the
binary.
Once we have a matching string for all parts, we can combine them to get the password.
