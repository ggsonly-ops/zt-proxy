#!/bin/sh
# usage: tools/adduser.sh <name> <group>   (reads the password from stdin)
[ $# -eq 2 ] || { echo "usage: $0 <name> <group>" >&2; exit 1; }
printf 'password: ' >&2
read -r password
hash=$(printf '%s' "$password" | sha256sum | cut -d' ' -f1)
echo "$1:$hash:$2" >> config/users.conf
