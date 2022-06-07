package plugin

import (
	"context"
	"fmt"
	"net"
	"strings"

	dTypes "github.com/docker/docker/api/types"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/devplayer0/docker-net-dhcp/pkg/udhcpc"
	"github.com/devplayer0/docker-net-dhcp/pkg/util"
)

// CLIOptionsKey is the key used in create network options by the CLI for custom options
const CLIOptionsKey string = "com.docker.network.generic"

// Implementations of the endpoints described in
// https://github.com/moby/libnetwork/blob/master/docs/remote.md

// CreateNetwork "creates" a new DHCP network (just checks if the provided bridge exists and the null IPAM driver is
// used)
func (p *Plugin) CreateNetwork(r CreateNetworkRequest) error {
	log.WithField("options", r.Options).Debug("CreateNetwork options")

	opts, err := decodeOpts(r.Options[util.OptionsKeyGeneric])
	if err != nil {
		return fmt.Errorf("failed to decode network options: %w", err)
	}

	if opts.Parent == "" {
		return util.ErrBridgeRequired
	}

	for _, d := range r.IPv4Data {
		if d.AddressSpace != "null" || d.Pool != "0.0.0.0/0" {
			return util.ErrIPAM
		}
	}

	if !parentExists(opts.Parent) {
		if err := createVlanLink(opts.Parent); err != nil {
			return err
		}
	}

	log.WithFields(log.Fields{
		"network": r.NetworkID,
		"parent":  opts.Parent,
		"ipv6":    opts.IPv6,
	}).Info("Network created")

	return nil
}

// DeleteNetwork "deletes" a DHCP network (does nothing, the bridge is managed by the user)
func (p *Plugin) DeleteNetwork(r DeleteNetworkRequest) error {
	log.WithField("network", r.NetworkID).Info("Network deleted")
	return nil
}

func vethPairNames(id string) (string, string) {
	return "dh-" + id[:12], id[:12] + "-dh"
}

func (p *Plugin) netOptions(ctx context.Context, id string) (DHCPNetworkOptions, error) {
	dummy := DHCPNetworkOptions{}

	n, err := p.docker.NetworkInspect(ctx, id, dTypes.NetworkInspectOptions{})
	if err != nil {
		return dummy, fmt.Errorf("failed to get info from Docker: %w", err)
	}

	opts, err := decodeOpts(n.Options)
	if err != nil {
		return dummy, fmt.Errorf("failed to parse options: %w", err)
	}

	return opts, nil
}

// CreateEndpoint creates a veth pair and uses udhcpc to acquire an initial IP address on the container end. Docker will
// move the interface into the container's namespace and apply the address.
func (p *Plugin) CreateEndpoint(ctx context.Context, r CreateEndpointRequest) (CreateEndpointResponse, error) {
	log.WithField("options", r.Options).Debug("CreateEndpoint options")
	res := CreateEndpointResponse{
		Interface: &EndpointInterface{},
	}

	if r.Interface != nil && (r.Interface.Address != "" || r.Interface.AddressIPv6 != "") {
		// TODO: Should we allow static IP's somehow?
		return res, util.ErrIPAM
	}

	opts, err := p.netOptions(ctx, r.NetworkID)
	if err != nil {
		return res, fmt.Errorf("failed to get network options: %w", err)
	}

	parent, err := netlink.LinkByName(opts.Parent)
	if err != nil {
		return res, fmt.Errorf("failed to get bridge interface: %w", err)
	}

	// hostName, ctrName := vethPairNames(r.EndpointID)
	hostName, _ := vethPairNames(r.EndpointID)
	la := netlink.NewLinkAttrs()
	la.Name = hostName
	la.ParentIndex = parent.Attrs().Index
	if r.Interface.MacAddress != "" {
		addr, err := net.ParseMAC(r.Interface.MacAddress)
		if err != nil {
			return res, util.ErrMACAddress
		}

		la.HardwareAddr = addr
	}

	hostLink := &netlink.Macvlan{
		LinkAttrs: la,
		Mode:      netlink.MACVLAN_MODE_BRIDGE,
	}

	if err := netlink.LinkAdd(hostLink); err != nil {
		return res, fmt.Errorf("failed to create veth pair: %w", err)
	}

	res.Interface.MacAddress = hostLink.Attrs().HardwareAddr.String()

	if err := func() error {
		if err := netlink.LinkSetUp(hostLink); err != nil {
			return fmt.Errorf("failed to set host side link of veth pair up: %w", err)
		}

		// ctrLink, err := netlink.LinkByName(ctrName)
		// if err != nil {
		// 	return fmt.Errorf("failed to find container side of veth pair: %w", err)
		// }
		// if err := netlink.LinkSetUp(ctrLink); err != nil {
		// 	return fmt.Errorf("failed to set container side link of veth pair up: %w", err)
		// }

		// Only write back the MAC address if it wasn't provided to us by libnetwork
		// if r.Interface.MacAddress == "" {
		// 	// The kernel will often reset a randomly assigned MAC address after actions like LinkSetMaster. We prevent
		// 	// this behaviour by setting it manually to the random value
		// 	// if err := netlink.LinkSetHardwareAddr(ctrLink, ctrLink.Attrs().HardwareAddr); err != nil {
		// 	if err := netlink.LinkSetHardwareAddr(hostLink, hostLink.Attrs().HardwareAddr); err != nil {
		// 		return fmt.Errorf("failed to set container side of veth pair's MAC address: %w", err)
		// 	}

		// 	res.Interface.MacAddress = hostLink.Attrs().HardwareAddr.String()
		// }

		// if err := netlink.LinkSetMaster(hostLink, bridge); err != nil {
		// 	return fmt.Errorf("failed to attach host side link of veth peer to bridge: %w", err)
		// }

		timeout := defaultLeaseTimeout
		if opts.LeaseTimeout != 0 {
			timeout = opts.LeaseTimeout
		}
		initialIP := func(v6 bool) error {
			v6str := ""
			if v6 {
				v6str = "v6"
			}

			timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			info, err := udhcpc.GetIP(timeoutCtx, hostName, &udhcpc.DHCPClientOptions{V6: v6})
			if err != nil {
				return fmt.Errorf("failed to get initial IP%v address via DHCP%v: %w", v6str, v6str, err)
			}

			// TODO fix empty bit mask part of IP.
			// In some cases we may have IP address CIDR without bit mask part:
			//     udhcpc -f -i eth0.207 -s /usr/lib/net-dhcp/udhcpc-handler -q -V docker-net-dhcp
			//         udhcpc: started, v1.30.1
			//         INFO[0000] {deconfig {  }}
			//         {"Type":"deconfig","Data":{"IP":"","Gateway":"","Domain":""}}
			//         udhcpc: sending discover
			//         udhcpc: sending select for 172.16.70.102
			//         udhcpc: lease of 172.16.70.102 obtained, lease time 600
			//         INFO[0000] {bound {172.16.70.102/  }}
			//         {"Type":"bound","Data":{"IP":"172.16.70.102/","Gateway":"","Domain":""}}
			if strings.HasSuffix(info.IP, "/") {
				info.IP = fmt.Sprintf("%s24", info.IP)
			}

			ip, err := netlink.ParseAddr(info.IP)
			if err != nil {
				return fmt.Errorf("failed to parse initial IP%v address: %w", v6str, err)
			}

			hint := p.joinHints[r.EndpointID]
			if v6 {
				res.Interface.AddressIPv6 = info.IP
				hint.IPv6 = ip
				// No gateways in DHCPv6!
			} else {
				res.Interface.Address = info.IP
				hint.IPv4 = ip
				hint.Gateway = info.Gateway
			}
			p.joinHints[r.EndpointID] = hint

			return nil
		}

		if err := initialIP(false); err != nil {
			return err
		}
		if opts.IPv6 {
			if err := initialIP(true); err != nil {
				return err
			}
		}

		return nil
	}(); err != nil {
		// Be sure to clean up the veth pair if any of this fails
		netlink.LinkDel(hostLink)
		return res, err
	}

	log.WithFields(log.Fields{
		"network":     r.NetworkID[:12],
		"endpoint":    r.EndpointID[:12],
		"mac_address": res.Interface.MacAddress,
		"ip":          res.Interface.Address,
		"ipv6":        res.Interface.AddressIPv6,
		"gateway":     fmt.Sprintf("%#v", p.joinHints[r.EndpointID].Gateway),
	}).Info("Endpoint created")

	return res, nil
}

type operInfo struct {
	Bridge      string `mapstructure:"bridge"`
	HostVEth    string `mapstructure:"veth_host"`
	HostVEthMAC string `mapstructure:"veth_host_mac"`
}

// EndpointOperInfo retrieves some info about an existing endpoint
func (p *Plugin) EndpointOperInfo(ctx context.Context, r InfoRequest) (InfoResponse, error) {
	res := InfoResponse{}

	opts, err := p.netOptions(ctx, r.NetworkID)
	if err != nil {
		return res, fmt.Errorf("failed to get network options: %w", err)
	}

	hostName, _ := vethPairNames(r.EndpointID)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return res, fmt.Errorf("failed to find host side of veth pair: %w", err)
	}

	info := operInfo{
		Bridge:      opts.Parent,
		HostVEth:    hostName,
		HostVEthMAC: hostLink.Attrs().HardwareAddr.String(),
	}
	if err := mapstructure.Decode(info, &res.Value); err != nil {
		return res, fmt.Errorf("failed to encode OperInfo: %w", err)
	}

	return res, nil
}

// DeleteEndpoint deletes the veth pair
func (p *Plugin) DeleteEndpoint(r DeleteEndpointRequest) error {
	hostName, _ := vethPairNames(r.EndpointID)
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("failed to lookup host veth interface %v: %w", hostName, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete veth pair: %w", err)
	}

	log.WithFields(log.Fields{
		"network":  r.NetworkID[:12],
		"endpoint": r.EndpointID[:12],
	}).Info("Endpoint deleted")

	return nil
}

func (p *Plugin) addRoutes(opts *DHCPNetworkOptions, v6 bool, bridge netlink.Link, r JoinRequest, hint joinHint, res *JoinResponse) error {
	family := unix.AF_INET
	if v6 {
		family = unix.AF_INET6
	}

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{
		LinkIndex: bridge.Attrs().Index,
		Type:      unix.RTN_UNICAST,
	}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TYPE)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	logFields := log.Fields{
		"network":  r.NetworkID[:12],
		"endpoint": r.EndpointID[:12],
		"sandbox":  r.SandboxKey,
	}
	for _, route := range routes {
		if route.Dst == nil {
			// Default route
			switch family {
			case unix.AF_INET:
				if res.Gateway == "" {
					res.Gateway = route.Gw.String()
					log.
						WithFields(logFields).
						WithField("gateway", res.Gateway).
						Info("[Join] Setting IPv4 gateway retrieved from bridge interface on host routing table")
				}
			case unix.AF_INET6:
				if res.GatewayIPv6 == "" {
					res.GatewayIPv6 = route.Gw.String()
					log.
						WithFields(logFields).
						WithField("gateway", res.GatewayIPv6).
						Info("[Join] Setting IPv6 gateway retrieved from bridge interface on host routing table")
				}
			}

			continue
		}

		if opts.SkipRoutes {
			// Don't do static routes at all
			continue
		}

		if route.Protocol == unix.RTPROT_KERNEL ||
			(family == unix.AF_INET && route.Dst.Contains(hint.IPv4.IP)) ||
			(family == unix.AF_INET6 && route.Dst.Contains(hint.IPv6.IP)) {
			// Make sure to leave out the default on-link route created automatically for the IP(s) acquired by DHCP
			continue
		}

		staticRoute := &StaticRoute{
			Destination: route.Dst.String(),
			// Default to an on-link route
			RouteType: 1,
		}
		res.StaticRoutes = append(res.StaticRoutes, staticRoute)

		if route.Gw != nil {
			staticRoute.RouteType = 0
			staticRoute.NextHop = route.Gw.String()

			log.
				WithFields(logFields).
				WithField("route", staticRoute.Destination).
				WithField("gateway", staticRoute.NextHop).
				Info("[Join] Adding route (via gateway) retrieved from bridge interface on host routing table")
		} else {
			log.
				WithFields(logFields).
				WithField("route", staticRoute.Destination).
				Info("[Join] Adding on-link route retrieved from bridge interface on host routing table")
		}
	}

	return nil
}

// Join passes the veth name and route information (gateway from DHCP and existing routes on the host bridge) to Docker
// and starts a persistent DHCP client to maintain the lease on the acquired IP
func (p *Plugin) Join(ctx context.Context, r JoinRequest) (JoinResponse, error) {
	log.WithField("options", r.Options).Debug("Join options")
	res := JoinResponse{}

	opts, err := p.netOptions(ctx, r.NetworkID)
	if err != nil {
		return res, fmt.Errorf("failed to get network options: %w", err)
	}

	hostName, _ := vethPairNames(r.EndpointID)

	res.InterfaceName = InterfaceName{
		SrcName:   hostName,
		DstPrefix: opts.Parent,
	}

	hint, ok := p.joinHints[r.EndpointID]
	if !ok {
		return res, util.ErrNoHint
	}
	delete(p.joinHints, r.EndpointID)

	if hint.Gateway != "" {
		log.WithFields(log.Fields{
			"network":  r.NetworkID[:12],
			"endpoint": r.EndpointID[:12],
			"sandbox":  r.SandboxKey,
			"gateway":  hint.Gateway,
		}).Info("[Join] Setting IPv4 gateway retrieved from initial DHCP in CreateEndpoint")
		res.Gateway = hint.Gateway
	}

	bridge, err := netlink.LinkByName(opts.Parent)
	if err != nil {
		return res, fmt.Errorf("failed to get bridge interface: %w", err)
	}

	if err := p.addRoutes(&opts, false, bridge, r, hint, &res); err != nil {
		return res, err
	}
	if opts.IPv6 {
		if err := p.addRoutes(&opts, true, bridge, r, hint, &res); err != nil {
			return res, err
		}
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), p.awaitTimeout)
		defer cancel()

		m := newDHCPManager(p.docker, r, opts)
		m.LastIP = hint.IPv4
		m.LastIPv6 = hint.IPv6

		if err := m.Start(ctx); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"network":  r.NetworkID[:12],
				"endpoint": r.EndpointID[:12],
				"sandbox":  r.SandboxKey,
			}).Error("Failed to start persistent DHCP client")
			return
		}

		p.persistentDHCP[r.EndpointID] = m
	}()

	log.WithFields(log.Fields{
		"network":  r.NetworkID[:12],
		"endpoint": r.EndpointID[:12],
		"sandbox":  r.SandboxKey,
	}).Info("Joined sandbox to endpoint")

	return res, nil
}

// Leave stops the persistent DHCP client for an endpoint
func (p *Plugin) Leave(ctx context.Context, r LeaveRequest) error {
	manager, ok := p.persistentDHCP[r.EndpointID]
	if !ok {
		return util.ErrNoSandbox
	}
	delete(p.persistentDHCP, r.EndpointID)

	if err := manager.Stop(); err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"network":  r.NetworkID[:12],
		"endpoint": r.EndpointID[:12],
	}).Info("Sandbox left endpoint")

	return nil
}
