package data

import (
	"net"
)

func GetHostIPs() (map[string]string, error) {
	// Retrieve a list of all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ipAddresses := make(map[string]string)

	// Iterate over each network interface
	for _, iface := range interfaces {
		// Skip interfaces that are down or loopback
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Retrieve the addresses assigned to this interface
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		// Iterate and add the address to the map if it is an IP address
		for _, addr := range addrs {
			// Check if the address is an IP address and not a MAC address
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ipAddresses[ipnet.IP.String()] = "hostIP"
		}
	}

	return ipAddresses, nil
}
