# 使用官方 PHP 8.2 + Apache 镜像
FROM php:8.2-apache

# 安装 relay.php 依赖的 curl 和 openssl 扩展
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    && docker-php-ext-install curl openssl

# 将仓库所有文件复制到 Apache 的网站根目录
COPY . /var/www/html/

# 确保 Apache 的 mod_rewrite 启用（可选，但建议）
RUN a2enmod rewrite

# 暴露 Apache 默认端口
EXPOSE 80
