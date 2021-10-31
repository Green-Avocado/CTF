#/usr/bin/sh

tshark -r public/tenbagger.pcapng -V | grep "Text"

