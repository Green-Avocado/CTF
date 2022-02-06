#!/usr/bin/bash

docker run --rm -p1337:1337 -p13337:13337 --cap-add=SYS_PTRACE -it dataeater
