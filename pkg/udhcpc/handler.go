package udhcpc

// Info contains env from udhcpc.
// Refer to https://github.com/iplinux/udhcp/blob/master/samples/sample.bound for example.
type Info struct {
	// $ip / $subnet in CIDR format. $subnet is an old-style netmask (non-CIDR).
	// You may use the following code to convert IPv4 netmask into CIDR format:
	//     net.IPMask(net.ParseIP(subnetValue).To4()).Size()
	IP string
	// $subnet
	Netmask string
	// $router
	Gateway string
	// $domain
	Domain string
	// $interface
	Interface string
	// $mtu
	MTU string
	// $dns is a list of nameservers/resolvers separated with spaces.
	DNS []string
}

type Event struct {
	Type string
	Data Info
}
