#!/bin/bash -e

# SOCK="/run/docker/plugins/macvlan2.sock"

sudo rm -f "${SOCK}"
sudo /home/vlakas/src/go/bin/go run cmd/net-dhcp/main.go -log trace
