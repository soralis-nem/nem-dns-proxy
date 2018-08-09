#!/bin/sh

export NODE_PATH=$NODE_PATH:/usr/local/lib/node_modules

case "$1" in
  start)
  exec forever --sourceDir=/usr/lib/node_modules/nem-dns-proxy -p /var/run/forever start nem-dns-proxy.js
  ;;

  stop)
  exec forever --sourceDir=/usr/lib/node_modules/nem-dns-proxy stop nem-dns-proxy.js
  ;;
esac

exit 0
