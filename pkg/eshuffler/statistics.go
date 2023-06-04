package eshuffler

import (
	"time"

	"github.com/sirupsen/logrus"
)

/*

 */

func (es *eShuffler) mapLog() {
	var tick uint32 = 0
	logrus.Info("Start Op Log:")
	for {
		tick++
		// xdpStats(tick, es)
		opStats(tick, es)
		time.Sleep(1 * time.Second)
	}
}

type bpfDataRec struct {
	Rx_packets uint64
	Rx_bytes   uint64
}

func xdpStats(tick uint32, es *eShuffler) {
	var tags = []string{"XDP_ABORTED", "XDP_DROP", "XDP_PASS", "XDP_TX", "XDP_REDIRECT"}
	var key uint32
	var val bpfDataRec

	if es.map_xdp_stats == nil {
		return
	}

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

	if es.map_op_stats == nil {
		return
	}

	var valid_indexs = []uint32{}
	for idx, op := range OP_LIST {
		if op != "" {
			valid_indexs = append(valid_indexs, uint32(idx))
		}
	}

	use_all_op, used_op := es.options.GetOpMode()

	if use_all_op {
		// alternately show all ops status
		key = tick % uint32(len(valid_indexs))
	} else {
		// show one op status if only one op is enabeld
		key = uint32(used_op)
	}

	var op_key = valid_indexs[key]
	var tag = OP_LIST[op_key]
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
