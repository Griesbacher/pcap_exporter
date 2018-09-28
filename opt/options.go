package opt

import (
	"fmt"
	"sort"
)

const (
	SourceAddress       = "SourceAddress"
	SourcePort          = "SourcePort"
	DestinationAddress  = "DestinationAddress"
	DestinationPort     = "DestinationPort"
	LinkProtocol        = "LinkProtocol"
	NetworkProtocol     = "NetworkProtocol"
	TransportProtocol   = "TransportProtocol"
	ApplicationProtocol = "ApplicationProtocol"
)

type ArgsLabels map[string]string

func (a ArgsLabels) String() string {
	result := ""
	for k, v := range a {
		result += fmt.Sprintf("%s: %s\n", k, v)
	}
	return result
}

type LabelKeys []string

type Options struct {
	LabelKeys   LabelKeys
	ResolveDNS  bool
	Device      string
	Filter      string
	Snaplen     int
	Promiscuous bool
}

func (o *Options) GetLabelKeys() LabelKeys {
	sort.Strings(o.LabelKeys)
	return o.LabelKeys
}

func (o Options) String() string {
	toPrint := "Labels:\n"
	for _, k := range o.GetLabelKeys() {
		toPrint += fmt.Sprintf("%s\n", k)
	}
	toPrint += fmt.Sprintf("\nResolveDNS: %t\n", o.ResolveDNS)
	toPrint += fmt.Sprintf("Device: %s\n", o.Device)
	toPrint += fmt.Sprintf("Filter: %s\n", o.Filter)
	toPrint += fmt.Sprintf("Snaplen: %d\n", o.Snaplen)
	toPrint += fmt.Sprintf("Promiscuous: %t\n", o.Promiscuous)
	return toPrint
}

func (o Options) HTMLString() []byte {
	toPrint := "<html><body><pre>\n"
	toPrint += o.String()
	return []byte(toPrint + "\n</pre></body></html>")
}
