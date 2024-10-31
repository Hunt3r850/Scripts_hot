#!/bin/bash

test -f /usr/bin/nmap

if [ "$(echo $?)" = "0" ]; then
        echo "Nmap esta instalado"
else
        echo "Nmap NO esta instalado" && sudo apt update > /dev/null && sudo apt install nmap -y > /dev/null
fi

ip=$1

ping -c 1 $ip > ping.log

for i in $(seq 60 70); do

        if test $(grep ttl=$i ping.log -c) = 1; then
                echo "Es un Linux"
fi
done

for i in $(seq 100 200); do

        if test $(grep ttl=$i ping.log -c) = 1; then
                echo "Es un Windows"
fi
done

rm ping.log

nmap -p- -sV -sC --open -sS -n -Pn $ip -on escaneo
