FROM node:20-alpine

# 安装 PHP 及其所需扩展
RUN apk add --no-cache \
    php83 php83-cli php83-curl php83-openssl \
    php83-mbstring php83-json php83-sockets \
    && ln -sf /usr/bin/php83 /usr/bin/php

WORKDIR /app

# 复制所有文件到容器
COPY . /app/

# 暴露 8080 端口
EXPOSE 8080

# 启动 Node.js 网关（它会自动拉起 PHP 后端）
CMD ["node", "/app/tunnel.js"]
