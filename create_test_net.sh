#!/bin/bash -e

: "${PARENT:=eth0}"
: "${NAME:=dhcp}"

docker network create -d net-dhcp --ipam-driver=null -o parent="${PARENT:?}" "${NAME:?}"
