package eshuffler

import (
	"time"

	"github.com/sirupsen/logrus"
)

/*

 */

func (es *eShuffler) mapLog() {
	var tick uint32 = 0
	if es.map_xdp_stats == nil {
		return
	}
	logrus.Info("Start Op Log:")
	for {
		tick++
		// xdpStats(tick, es)
		opStats(tick, es)
		time.Sleep(1 * time.Second)
	}
}

func xdpStats(tick uint32, es *eShuffler) {
	var tags = []string{"XDP_ABORTED", "XDP_DROP", "XDP_PASS", "XDP_TX", "XDP_REDIRECT"}
	var key uint32
	var val bpfDataRec

	key = tick % uint32(len(tags))
	if err := es.map_xdp_stats.Lookup(&key, &val); err == nil {
		logrus.Infof("status %s %v", tags[key], val)
	} else {
		logrus.Errorf("bpf syscall: got %v :)", err)
		return
	}
}

func opStats(tick uint32, es *eShuffler) {
	var key uint32
	var val uint32

	var index = []uint32{2, 4, 5}
	key = tick % uint32(len(index))
	var tags = []string{mode_func[MODE_OP2], mode_func[MODE_OP4], mode_func[MODE_OP5]}
	var op_key = index[key]
	var tag = tags[key]

	op_num, mode := es.options.GetMode()
	// show only one mode
	if op_num == 1 {
		op_key = uint32(mode_index[mode])
		tag = mode_func[mode]
	}

	var all uint32 = 0
	var err error
	var all_pkt_key = uint32(0)
	if err = es.map_op_stats.Lookup(&all_pkt_key, &all); err != nil {
		logrus.Errorf("bpf syscall: got %v :)", err)
	}

	if err = es.map_op_stats.Lookup(&op_key, &val); err == nil {
		logrus.Infof("status %s %d/%d", tag, val, all)
	} else {
		logrus.Errorf("bpf syscall: got %v :)", err)
		return
	}
}
