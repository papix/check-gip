package checkgip

import (
	"fmt"
	"net"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/mackerelio/checkers"
)

type checkGipOpts struct {
	Host      string `long:"host"`
	Interface string `short:"i" long:"interface"`
}

func Do() {
	ckr := Run(os.Args[1:])
	ckr.Name = "GIP"
	ckr.Exit()
}

func Run(args []string) *checkers.Checker {
	opts := checkGipOpts{}
	_, err := flags.ParseArgs(&opts, args)
	if err != nil {
		os.Exit(1)
	}

	lookupedAddrs, err := net.LookupHost(opts.Host)
	if err != nil {
		return checkers.NewChecker(checkers.CRITICAL, fmt.Sprintf("Failed to lookup host: %s", opts.Host))
	}

	interfaceAddr, err := getAddrByInterface(opts.Interface)
	if err != nil {
		return checkers.NewChecker(checkers.CRITICAL, err.Error())
	}

	for _, addr := range lookupedAddrs {
		if addr == interfaceAddr {
			return checkers.NewChecker(checkers.OK, fmt.Sprintf("Can reach '%s' (%s) with %s", opts.Interface, interfaceAddr, opts.Host))
		}
	}
	return checkers.NewChecker(checkers.CRITICAL, fmt.Sprintf("Can not reach '%s' (%s) with %s", opts.Interface, interfaceAddr, opts.Host))
}

func getAddrByInterface(iface string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("Failed to get interfaces")
	}

	for _, i := range ifaces {
		if i.Name == iface {
			addrs, err := i.Addrs()
			if err != nil {
				return "", fmt.Errorf("Failed to addresses from interface: %s", i.Name)
			}

			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					return ipnet.IP.String(), nil
				}
			}

			return "", fmt.Errorf("'%s' does not have an appropriate address", iface)
		}
	}

	return "", fmt.Errorf("Interface not found: %s", iface)
}
