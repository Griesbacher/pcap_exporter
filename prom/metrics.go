package prom

import (
	"github.com/griesbacher/pcap_exporter/opt"
	"github.com/prometheus/client_golang/prometheus"
)

const NameSpace = "pcap"

var (
	Overall   *prometheus.GaugeVec
	BufferLen = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: NameSpace,
			Name:      "buffer_len",
			Help:      "Fill state of the internal buffer",
		},
	)
	PackagesSeen = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: NameSpace,
			Name:      "packages_seen",
			Help:      "Amount of packages seen",
		},
	)
	DNSQueryDuration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: NameSpace,
			Name:      "dns_query_duration",
			Help:      "Duration in seconds per DNS query",
		},
	)
)

func InitMetrics(options opt.Options) {
	Overall = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: NameSpace,
			Name:      "bytes_transfered",
			Help:      "Amount of bytes transfered",
		},
		options.GetLabelKeys(),
	)
	prometheus.MustRegister(Overall)
	prometheus.MustRegister(BufferLen)
	prometheus.MustRegister(PackagesSeen)
	prometheus.MustRegister(DNSQueryDuration)
}
