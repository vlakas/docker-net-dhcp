#!/bin/bash

if ! command -v docker >/dev/null; then
	1>&2 echo "ERROR docker command not found."
	exit 0
fi

if ! command -v ip >/dev/null; then
	1>&2 echo "ERROR ip command not found."
	exit 0
fi

docker network ls -qf 'driver=net-dhcp' | while read -r NET; do
	PARENT="$(docker inspect --format='{{.Options.parent}}' $NET)"
	if [ "$PARENT" == "<no value>" ]; then
		1>&2 echo "ERROR Network $NET has not parent."
		continue
	fi

	VLAN_ID="$(echo "$PARENT" | grep -oP '(?<=\.)\d+$')"
	if [ -z "$VLAN_ID" ]; then
		1>&2 echo "WARNING No VLAN ID for parent interface $PARENT"
		continue
	fi

	if ip link show "$PARENT">/dev/null; then
		continue
	fi

	1>&2 echo "WARNING Parent interface $PARENT does not exist. Create it"
	ip link add link eth0 name "$PARENT" type vlan id "$VLAN_ID" && \
		ip link set "$PARENT" up
done
