package main

import (
	"flag"
	"log/syslog"
	"net"
	"os"
	"os/signal"
	"time"

	log "github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
	"golang.org/x/sys/unix"

	"github.com/coreos/go-systemd/activation"
	"github.com/devplayer0/docker-net-dhcp/pkg/plugin"
)

var (
	logLevel = flag.String("log", "", "log level")
	logFile  = flag.String("logfile", "", "log file")
	bindSock = flag.String("sock", "", "bind unix socket")
	nosyslog = flag.Bool("nosyslog", false, "Disable syslog logging")
	debug    = flag.Bool("debug", false, "Turn on debug logging")
)

func main() {
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{})

	if !*nosyslog {
		sl, err := lSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "net-dhcp")
		if err == nil {
			log.AddHook(sl)
		}
	}

	log.SetLevel(log.InfoLevel)

	if *debug {
		log.SetReportCaller(true)
		log.SetLevel(log.DebugLevel)
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.WithError(err).Fatal("Failed to open log file for writing")
		}
		defer f.Close()

		log.StandardLogger().Out = f
	}

	awaitTimeout := 5 * time.Second
	var err error
	if t, ok := os.LookupEnv("AWAIT_TIMEOUT"); ok {
		awaitTimeout, err = time.ParseDuration(t)
		if err != nil {
			log.WithError(err).Fatal("Failed to parse await timeout")
		}
	}

	p, err := plugin.NewPlugin(awaitTimeout)
	if err != nil {
		log.WithError(err).Fatal("Failed to create plugin")
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	var listener net.Listener

	if len(*bindSock) == 0 {
		listeners, err := activation.Listeners()
		if err != nil {
			log.WithError(err).Fatal("Failed to get socket listener(s) from systemd")
		}

		if len(listeners) == 0 {
			log.Fatal("Got 0 listeners from systemd")
		}

		listener = listeners[0]
	} else {
		listener, err = plugin.SocketListener(*bindSock)
		if err != nil {
			log.WithError(err).Fatal("Failed to bind to unix socket")
		}
	}

	go func() {
		et := log.WithFields(log.Fields{
			"socket": listener.Addr().String(),
		})
		et.Info("Starting server...")
		if err := p.Listen(listener); err != nil {
			et.WithError(err).Fatal("Failed to start plugin")
		}
	}()

	<-sigs
	log.Info("Shutting down...")
	if err := p.Close(); err != nil {
		log.WithError(err).Fatal("Failed to stop plugin")
	}
}
