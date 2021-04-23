#!/bin/bash
docker rm -f web_the_galactic_times
docker build -t web_the_galactic_times . && \
docker run --name=web_the_galactic_times --rm -p1337:1337 -it web_the_galactic_times