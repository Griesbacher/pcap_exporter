package main

import (
	"flag"
	"fmt"
	"github.com/griesbacher/pcap_exporter/dns"
	"github.com/griesbacher/pcap_exporter/opt"
	"github.com/griesbacher/pcap_exporter/pcap"
	"github.com/griesbacher/pcap_exporter/prom"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

const (
	version                  = 0.1
	labelFormatString string = "Add %s to labels."
)

func printLabel(label string) string {
	return fmt.Sprintf(labelFormatString, label)
}

var (
	device      = flag.String("i", "any", "interface name to listen to. 'any' listens to all.")
	filter      = flag.String("f", "", "pcap filter. See: http://www.tcpdump.org/manpages/pcap-filter.7.html")
	snaplen     = flag.Int("s", 65536, "number of bytes max to read per packet.")
	address     = flag.String("listen-address", ":9999", "The address for the exporter.")
	promiscuous = flag.Bool("p", false, "use promiscuous mode.")
	resolve     = flag.Bool("r", false, "Resolve ip addresses with thier DNS names.")

	listInterfaces = flag.Bool("list-interfaces", false, "Prints available interfaces and quits.")

	sa = flag.Bool("l-sa", true, printLabel(opt.SourceAddress))
	sp = flag.Bool("l-sp", false, printLabel(opt.SourcePort))
	da = flag.Bool("l-da", true, printLabel(opt.DestinationAddress))
	dp = flag.Bool("l-dp", false, printLabel(opt.DestinationPort))

	lp = flag.Bool("l-lp", false, printLabel(opt.LinkProtocol))
	np = flag.Bool("l-np", false, printLabel(opt.NetworkProtocol))
	tp = flag.Bool("l-tp", false, printLabel(opt.TransportProtocol))
	ap = flag.Bool("l-ap", false, printLabel(opt.ApplicationProtocol))

	labelFlags = map[*bool]string{
		sa: opt.SourceAddress,
		sp: opt.SourcePort,
		da: opt.DestinationAddress,
		dp: opt.DestinationPort,

		lp: opt.LinkProtocol,
		np: opt.NetworkProtocol,
		tp: opt.TransportProtocol,
		ap: opt.ApplicationProtocol,
	}
)

func main() {
	// handle args
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "PCAP_exporter\n" +
			"Copyright (c) 2017 Philip Griesbacher\n"+
			"Version: %s\n" +
			"https://github.com/Griesbacher/pcap_exporter",
			version)
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Note:\n"+
			"- If 'l-sa' or 'l-da' is used but no address can be determent, '%s' will be set as label value.\n"+
			"- If 'l-sp' or 'l-dp' is used but no port can be determent, '%s' will be set as label value.\n"+
			"- If any protocol is used but no protocol can be determent, '' will be set as label value.\n\n",
			pcap.EscapeIP, pcap.EscapePort,
		)
		flag.PrintDefaults()
	}
	options := parseFlags()

	if *listInterfaces {
		fmt.Fprint(os.Stderr, "Available interfaces:\n\n")
		fmt.Fprint(os.Stderr, pcap.ListAvailableInterfaces())
		os.Exit(1)
	}

	// listen for sigterm
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Fatal("Recieved SigTerm, quitting now...")
		pcap.StopListen()
		dns.Close <- true
		os.Exit(1)
	}()

	// init prometheus metrics
	prom.InitMetrics(options)

	// start pcap listener
	go pcap.StartListen(*device, *filter, *snaplen, *promiscuous, options)

	// start prometheus web server
	log.Infof("Starting exporter at: %s", *address)
	log.Infof("Metrics are available at: %s/metrics", *address)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/options", func(w http.ResponseWriter, r *http.Request) {
		w.Write(options.HTMLString())
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
<html>
	<head>
		<title>PCAP Exporter</title>
	</head>
	<body>
		<h1>PCAP Exporter</h1>
		<p>
			<a href='/metrics'>Metrics</a>
		</p>
		<p>
			<a href='/options'>Options</a>
		</p>
		<p>
			<a href='https://github.com/griesbacher/pcap_exporter'>Source / Github</a>
		</p>
	</body>
</html>`))
	})
	log.Fatal(http.ListenAndServe(*address, nil))
}

func parseFlags() opt.Options {
	flag.Parse()
	labelKeys := []string{}
	for label, key := range labelFlags {
		if label != nil && *label {
			labelKeys = append(labelKeys, key)
		}
	}

	options := opt.Options{
		LabelKeys:   labelKeys,
		Device:      *device,
		Filter:      *filter,
		Snaplen:     *snaplen,
		Promiscuous: *promiscuous,
		ResolveDNS:  *resolve,
	}
	return options
}
