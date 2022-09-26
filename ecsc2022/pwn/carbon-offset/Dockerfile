# docker build -t carbon_offset .
# docker run --rm -p 9001:1337 carbon_offset:latest 
# nc 127.0.0.1 9001

# Ubuntu 22.04    
FROM ubuntu@sha256:42ba2dfce475de1113d55602d40af18415897167d47c2045ec7b6d9746ff148f as ubuntu-22.04
RUN apt-get update && apt-get install -y socat gdbserver
RUN adduser --no-create-home --disabled-password --gecos "" ctf
WORKDIR /home/ctf    
COPY --chown=root:ctf carbon_offset flag.txt ./     
RUN chmod 2750 carbon_offset && \
    chmod 0640 flag.txt      
CMD ["socat", "tcp-listen:1337,fork,reuseaddr", "exec:./carbon_offset"]
EXPOSE 1337
