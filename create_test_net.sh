#!/bin/bash -e

: "${PARENT:=eth0}"
: "${NAME:=dhcp}"

docker network create -d net-dhcp --ipam-driver=null -o parent="${PARENT:?}" -o subnet=192.168.8.0/24 -o gateway=192.168.8.254 "${NAME:?}"
