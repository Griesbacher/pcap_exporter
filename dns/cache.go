package dns

import (
	"github.com/griesbacher/pcap_exporter/prom"
	"net"
	"sync"
	"time"
)

var (
	cache = map[string]string{}
	mutex = sync.Mutex{}
	Close = make(chan bool)
)

func init() {
	go func() {
		for true {
			select {
			case <-Close:
				return
			case <-time.After(10 * time.Minute):
				mutex.Lock()
				cache = map[string]string{}
				mutex.Unlock()
			}
		}
	}()
}

func LookupAddr(ip string) string {
	mutex.Lock()
	if name, ok := cache[ip]; ok {
		mutex.Unlock()
		return name
	}
	mutex.Unlock()

	start := time.Now()
	names, err := net.LookupAddr(ip)
	prom.DNSQueryDuration.Add(time.Now().Sub(start).Seconds())

	if err != nil || len(names) == 0 {
		names = []string{ip}
	}
	mutex.Lock()
	cache[ip] = names[0]
	mutex.Unlock()
	return names[0]
}
