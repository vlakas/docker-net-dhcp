#!/bin/bash -e

# Package version for deb package. Must be [0-9]+.[0-9]+.[0-9]+.
# : "${VERSION="$(git describe | grep -oP '(?<=v)\d+\.\d+\.\d+')"}"

VERSION="0.1.4"

: "${PKG_ROOT=package-net-dhcp}"
: "${DEB_NAME=docker-net-dhcp-${VERSION:?}_amd64.deb}"
: "${DST=./}"

echo "Building package $VERSION"
echo "You may specify version in VERSION env var"

if [ -d "$PKG_ROOT" ]; then
	read -r -p "WARNING $PKG_ROOT exists. Do you want to remove it? [Y/n] " -n 1 DO_RM
	case $DO_RM in
		Y|y)
			rm -rf "$PKG_ROOT"
			;;
		N|n)
			exit 1
			;;
		*)
			if [ -z "$DO_RM" ]; then
				rm -rf "$PKG_ROOT"
			else
				echo "ERROR Unknown option $DO_RM"
				exit 1
			fi
	esac
fi

mkdir -p "$PKG_ROOT/DEBIAN"

cp scripts/postinst "$PKG_ROOT/DEBIAN/"
cp scripts/prerm "$PKG_ROOT/DEBIAN/"

cat << EOF > "$PKG_ROOT/DEBIAN/control"
Package: docker-net-dhcp
Version: $VERSION
Maintainer: Vladyslav Zakhozhai <vlad@labyrint.tech>
Architecture: amd64
Depends: udhcpc
Description: Labyrint appliances TextUI menu
EOF

mkdir -p "$PKG_ROOT/usr/lib/net-dhcp"

CGO_ENABLED=0 go build -o "$PKG_ROOT/usr/lib/net-dhcp/net-dhcp" -ldflags="-extldflags=-static" -trimpath cmd/net-dhcp/main.go
CGO_ENABLED=0 go build -o "$PKG_ROOT/usr/lib/net-dhcp/udhcpc-handler" -ldflags="-extldflags=-static" -trimpath cmd/udhcpc-handler/main.go

dpkg-deb --build "$PKG_ROOT" && \
	mv "${PKG_ROOT}.deb" "$DST/$DEB_NAME"
