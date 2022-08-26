package main

import (
	"net"

	"github.com/vishvananda/netlink"
)

func main() {
	const parentName string = "eth0"
	const macStr string = "18:31:bf:01:12:33"

	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		panic(err)
	}

	mac, err := net.ParseMAC(macStr)
	if err != nil {
		panic(err)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = "mc"
	attrs.ParentIndex = parent.Attrs().Index
	attrs.HardwareAddr = mac

	macvlan := &netlink.Macvlan{
		LinkAttrs: attrs,
		Mode:      netlink.MACVLAN_MODE_BRIDGE,
	}

	if err := netlink.LinkAdd(macvlan); err != nil {
		panic(err)
	}

	if err := netlink.LinkSetUp(macvlan); err != nil {
		panic(err)
	}
}
