package eshuffler

import (
	"time"

	"github.com/sirupsen/logrus"
)

/*

 */

func (es *eShuffler) mapLog() {
	var key uint32
	var val bpfDataRec

	var tick uint32 = 0
	var tags = []string{"XDP_ABORTED", "XDP_DROP", "XDP_PASS", "XDP_TX", "XDP_REDIRECT"}
	if es.map_xdp_stats == nil {
		return
	}
	logrus.Info("Start Op Log:")
	for {
		tick++
		key = tick % uint32(len(tags))
		if err := es.map_xdp_stats.Lookup(&key, &val); err == nil {
			logrus.Infof("status %s %v", tags[key], val)
		} else {
			logrus.Errorf("bpf syscall: got %v :)", err)
			return
		}
		time.Sleep(1 * time.Second)
	}
}
