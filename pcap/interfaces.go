package pcap

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/common/log"
)

func ListAvailableInterfaces() (toPrint string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		toPrint += fmt.Sprintf(
			"Name: %s\nDescription: %s\n",
			device.Name, device.Description)
		if len(device.Addresses) > 0 {
			toPrint += "Devices addresses:\n"
			for _, address := range device.Addresses {
				toPrint += fmt.Sprintf(
					" - IP address: %s\n - Subnet mask: %s\n",
					address.IP, address.Netmask,
				)
			}
		}
		toPrint += "\n"
	}
	return toPrint
}
