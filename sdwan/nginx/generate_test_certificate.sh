#!/bin/sh
set -eu
install -d -m 0755 /etc/nginx/tls
if [ ! -s /etc/nginx/tls/lab.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj '/CN=sdwan-lab.local/O=SDWAN Research Lab' \
    -keyout /etc/nginx/tls/lab.key -out /etc/nginx/tls/lab.crt
  chmod 0600 /etc/nginx/tls/lab.key
fi


