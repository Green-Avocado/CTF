from debian:bullseye

RUN apt-get -y update && apt-get -y install socat gdbserver htop

COPY dataeater .

CMD gdbserver --multi localhost:13337 & socat TCP-LISTEN:1337,fork,reuseaddr EXEC:"./dataeater" & htop
