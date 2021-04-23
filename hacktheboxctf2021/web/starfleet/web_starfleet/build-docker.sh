#!/bin/bash
docker build --no-cache --tag=web_starfleet .
docker run -p 1337:1337 --name=web_starfleet --rm web_starfleet
