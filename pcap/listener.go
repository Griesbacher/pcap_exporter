package pcap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/griesbacher/pcap_exporter/opt"
	"github.com/griesbacher/pcap_exporter/prom"
	"github.com/prometheus/common/log"
	"runtime"
)

var workerSlice = make([]*worker, runtime.NumCPU())

func StartListen(device, filter string, snaplen int, promiscuous bool, options opt.Options) {
	// start capture packets
	handle, err := pcap.OpenLive(device, int32(snaplen), promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// start package workers
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetStream := make(chan gopacket.Packet, 1000)
	for i := 0; i < len(workerSlice); i++ {
		workerSlice[i] = NewWorker(packetStream, options)
	}

	log.Debug("Started PCAP-Listener")
	for packet := range packetSource.Packets() {
		prom.PackagesSeen.Add(1)
		packetStream <- packet
	}
}

func StopListen() {
	for _, w := range workerSlice {
		w.Stop()
	}
}
