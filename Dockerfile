FROM node:20-alpine

RUN apk add --no-cache \
    php83 php83-cli php83-curl php83-openssl \
    php83-mbstring php83-json php83-sockets \
    && ln -sf /usr/bin/php83 /usr/bin/php

WORKDIR /app
COPY . /app/

EXPOSE 8080
CMD ["node", "/app/tunnel.js"]
