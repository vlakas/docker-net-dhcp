package main

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"

	"github.com/devplayer0/docker-net-dhcp/pkg/udhcpc"
)

var debug bool

func main() {
	log.SetFormatter(&log.TextFormatter{})

	sl, err := lSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "udhcpc-handler")
	if err == nil {
		log.AddHook(sl)
	}

	if debug {
		log.SetReportCaller(true)
		log.SetLevel(log.DebugLevel)
	}

	log.AddHook(sl)

	if len(os.Args) != 2 {
		log.Fatalf("Usage: %v <event type>", os.Args[0])
		return
	}

	event := udhcpc.Event{
		Type: os.Args[1],
	}

	switch event.Type {
	case "bound", "renew":
		if v6, ok := os.LookupEnv("ipv6"); ok {
			// Clean up the IP (udhcpc6 emits a _lot_ of zeros)
			_, netV6, err := net.ParseCIDR(v6 + "/128")
			if err != nil {
				log.WithError(err).Warn("Failed to parse IPv6 address")
			}

			event.Data.IP = netV6.String()
		} else {
			var mask string
			netmask := net.ParseIP(os.Getenv("subnet"))
			if netmask != nil {
				m, _ := net.IPMask(netmask.To4()).Size()
				if m > 0 {
					mask = fmt.Sprintf("%d", m)
				}
			}

			if len(mask) == 0 {
				log.Errorf("Failed to parse netmask/subnet value: %v", os.Getenv("subnet"))
			}

			event.Data.IP = os.Getenv("ip") + "/" + mask
			event.Data.Netmask = os.Getenv("subnet")
			event.Data.Gateway = os.Getenv("router")
			event.Data.Domain = os.Getenv("domain")
			event.Data.Interface = os.Getenv("interface")
			event.Data.MTU = os.Getenv("mtu")
			event.Data.DNS = strings.Split(os.Getenv("dns"), " ")
		}
	case "deconfig", "leasefail", "nak":
	default:
		log.Warnf("Ignoring unknown event type `%v`", event.Type)
		return
	}

	log.Info(event)

	if err := json.NewEncoder(os.Stdout).Encode(event); err != nil {
		log.WithError(err).Fatalf("Failed to encode udhcpc event")
		return
	}
}
