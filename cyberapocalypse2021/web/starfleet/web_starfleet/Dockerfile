FROM node:current-buster-slim

# Install packages
RUN apt update -y; apt install -y supervisor gcc netcat curl

# Setup app
RUN mkdir -p /app

# Add application
WORKDIR /app
COPY challenge .

# Install node-js dependencies
RUN yarn

# Add readflag binary
COPY readflag.c /
RUN gcc -o /readflag /readflag.c && chmod 4755 /readflag && rm /readflag.c

# Copy flag
COPY flag /root/flag

# Expose the port node-js is reachable on
EXPOSE 1337

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]