#!/bin/sh

mkdir -pv /etc/binfreeze
echo "Populating /etc/binfreeze/allow.conf"
find / -type f -perm /111 2>/dev/null | sort -u > /etc/binfreeze/allow.conf