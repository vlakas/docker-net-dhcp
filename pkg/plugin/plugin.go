package plugin

import (
	"fmt"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"time"

	docker "github.com/docker/docker/client"
	"github.com/gorilla/handlers"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/devplayer0/docker-net-dhcp/pkg/util"
)

// DriverName is the name of the Docker Network Driver
const DriverName string = "net-dhcp"

const defaultLeaseTimeout = 10 * time.Second

var driverRegexp = regexp.MustCompile(`^ghcr\.io/devplayer0/docker-net-dhcp:.+$`)

// IsDHCPPlugin checks if a Docker network driver is an instance of this plugin
func IsDHCPPlugin(driver string) bool {
	return driverRegexp.MatchString(driver)
}

// DHCPNetworkOptions contains options for the DHCP network driver
type DHCPNetworkOptions struct {
	Parent          string
	IPv6            bool
	LeaseTimeout    time.Duration `mapstructure:"lease_timeout"`
	IgnoreConflicts bool          `mapstructure:"ignore_conflicts"`
	SkipRoutes      bool          `mapstructure:"skip_routes"`
	Subnet          *net.IPNet
	Gateway         net.IP
}

func StringToIPHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		switch t {
		case reflect.TypeOf(net.IPNet{}):
			ipStr := data.(string)

			if len(ipStr) == 0 {
				return data, nil
			}

			_, cidr, err := net.ParseCIDR(ipStr)
			if err != nil {
				return data, err
			}

			log.Debugf("Dis is CIDR: %v %T", cidr, cidr)

			return cidr, nil
		case reflect.TypeOf(net.IP{}):
			ipStr := data.(string)
			if len(ipStr) == 0 {
				return data, nil
			}

			ip := net.ParseIP(ipStr)
			if ip == nil {
				return data, fmt.Errorf("failed to parse gateway IP address: %v", ipStr)
			}

			log.Debugf("Dis is IP: %v %T", ip, ip)
			return ip, nil
		default:
			return data, nil
		}

		// if f.Kind() != reflect.String {
		// 	return data, nil
		// }
		// if t != reflect.TypeOf(time.Duration(5)) {
		// 	return data, nil
		// }

		// // Convert it by parsing
		// return time.ParseDuration(data.(string))
	}
}

func decodeOpts(input interface{}) (DHCPNetworkOptions, error) {
	var opts DHCPNetworkOptions
	optsDecoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &opts,
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			StringToIPHookFunc(),
		),
	})
	if err != nil {
		return opts, fmt.Errorf("failed to create options decoder: %w", err)
	}

	if err := optsDecoder.Decode(input); err != nil {
		return opts, err
	}

	return opts, nil
}

type joinHint struct {
	IPv4    *netlink.Addr
	IPv6    *netlink.Addr
	Gateway string
}

// Plugin is the DHCP network plugin
type Plugin struct {
	awaitTimeout time.Duration

	docker *docker.Client
	server http.Server

	joinHints      map[string]joinHint
	persistentDHCP map[string]*dhcpManager
}

// NewPlugin creates a new Plugin
func NewPlugin(awaitTimeout time.Duration) (*Plugin, error) {
	client, err := docker.NewClient("unix:///run/docker.sock", "v1.13.1", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	p := Plugin{
		awaitTimeout: awaitTimeout,

		docker: client,

		joinHints:      make(map[string]joinHint),
		persistentDHCP: make(map[string]*dhcpManager),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/Plugin.Activate", p.apiActivate)
	mux.HandleFunc("/NetworkDriver.GetCapabilities", p.apiGetCapabilities)

	mux.HandleFunc("/NetworkDriver.CreateNetwork", p.apiCreateNetwork)
	mux.HandleFunc("/NetworkDriver.DeleteNetwork", p.apiDeleteNetwork)

	mux.HandleFunc("/NetworkDriver.CreateEndpoint", p.apiCreateEndpoint)
	mux.HandleFunc("/NetworkDriver.EndpointOperInfo", p.apiEndpointOperInfo)
	mux.HandleFunc("/NetworkDriver.DeleteEndpoint", p.apiDeleteEndpoint)

	mux.HandleFunc("/NetworkDriver.Join", p.apiJoin)
	mux.HandleFunc("/NetworkDriver.Leave", p.apiLeave)

	p.server = http.Server{
		Handler: handlers.CustomLoggingHandler(nil, mux, util.WriteAccessLog),
	}

	return &p, nil
}

// Listen starts the plugin server
func (p *Plugin) Listen(bindSock string) error {
	l, err := net.Listen("unix", bindSock)
	if err != nil {
		return err
	}

	return p.server.Serve(l)
}

// Close stops the plugin server
func (p *Plugin) Close() error {
	if err := p.docker.Close(); err != nil {
		return fmt.Errorf("failed to close docker client: %w", err)
	}

	if err := p.server.Close(); err != nil {
		return fmt.Errorf("failed to close http server: %w", err)
	}

	return nil
}
