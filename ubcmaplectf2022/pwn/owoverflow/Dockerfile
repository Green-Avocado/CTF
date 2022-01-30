FROM ubuntu:20.04

RUN apt-get update && apt-get -y install xinetd

RUN useradd -M ctf

WORKDIR /ctf

COPY xinetd.conf ./
COPY challenge.sh ./
COPY banner_fail ./
COPY flag.txt ./
COPY owoverflow ./

CMD ["xinetd", "-dontfork", "-f", "xinetd.conf"]
