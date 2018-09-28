package pcap

import (
	"github.com/google/gopacket"
	"github.com/griesbacher/pcap_exporter/dns"
	"github.com/griesbacher/pcap_exporter/opt"
	"github.com/griesbacher/pcap_exporter/prom"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"time"
)

var escapeEndpointAddress = gopacket.NewEndpoint(-1, []byte(""))
var escapeEndpointPort = gopacket.NewEndpoint(-2, []byte(""))

const (
	EscapeIP   = "-1.-1.-1.-1"
	EscapePort = "-1"
)

type worker struct {
	stop        chan bool
	packetInput chan gopacket.Packet
	options     opt.Options
}

func NewWorker(packetInput chan gopacket.Packet, options opt.Options) *worker {
	w := &worker{
		stop:        make(chan bool),
		packetInput: packetInput,
		options:     options,
	}
	go w.run()
	return w
}

func (w worker) Stop() bool {
	select {
	case w.stop <- true:
		select {
		case <-w.stop:
			return true
		case <-time.After(200 * time.Millisecond):
			log.Warn("Killing Worker, due not acknowledge stop")
		}
	case <-time.After(200 * time.Millisecond):
		log.Warn("Killing Worker, due not excepting stop")
	}
	return false
}

func (w worker) run() {
	running := true
	for running {
		select {
		case <-w.stop:
			running = false
			w.stop <- true
		case packet := <-w.packetInput:
			if packet != nil {
				w.handlePacket(packet)
			}
			prom.BufferLen.Set(float64(len(w.packetInput)))
		}
	}
}

func (w worker) handlePacket(packet gopacket.Packet) {
	packetSize := float64(len(packet.Data()))

	srcAdr, dstAdr := escapeEndpointAddress, escapeEndpointAddress
	if packet.NetworkLayer() != nil {
		srcAdr, dstAdr = packet.NetworkLayer().NetworkFlow().Endpoints()
	}

	srcPort, dstPort := escapeEndpointPort, escapeEndpointPort
	if packet.TransportLayer() != nil {
		srcPort, dstPort = packet.TransportLayer().TransportFlow().Endpoints()
	}

	labels := prometheus.Labels{}
	for _, key := range w.options.GetLabelKeys() {
		switch key {
		case opt.DestinationAddress:
			labels[key] = w.printEndpoint(dstAdr)
		case opt.DestinationPort:
			labels[key] = w.printEndpoint(dstPort)
		case opt.SourceAddress:
			labels[key] = w.printEndpoint(srcAdr)
		case opt.SourcePort:
			labels[key] = w.printEndpoint(srcPort)
		case opt.LinkProtocol, opt.NetworkProtocol, opt.TransportProtocol, opt.ApplicationProtocol:
			labels[key] = printProtocol(packet, key)
		default:
			log.Warnf("Got unknown label key: %s", key)
		}
	}
	prom.Overall.With(labels).Add(packetSize)
}

func (w worker) printEndpoint(e gopacket.Endpoint) string {
	if e.EndpointType() == -1 {
		return EscapeIP
	} else if e.EndpointType() == -2 {
		return EscapePort
	}

	if w.options.ResolveDNS {
		return dns.LookupAddr(e.String())
	}
	return e.String()
}

func printProtocol(packet gopacket.Packet, layer string) string {
	switch layer {
	case opt.LinkProtocol:
		if packet.LinkLayer() != nil {
			return packet.LinkLayer().LayerType().String()
		}
	case opt.NetworkProtocol:
		if packet.NetworkLayer() != nil {
			return packet.NetworkLayer().LayerType().String()
		}
	case opt.TransportProtocol:
		if packet.TransportLayer() != nil {
			return packet.TransportLayer().LayerType().String()
		}
	case opt.ApplicationProtocol:
		if packet.ApplicationLayer() != nil {
			return packet.ApplicationLayer().LayerType().String()
		}
	}
	return ""
}
