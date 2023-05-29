package eshuffler

import (
	_ "embed"
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"
)

//go:embed bin/bpf.o
var ProbeTC []byte

const (
	MODE_OP1 = 0b1
	MODE_OP2 = 0b10
	MODE_OP3 = 0b100
	MODE_OP4 = 0b1000
	MODE_OP5 = 0b10000
	MODE_OP6 = 0b100000
)

var mode_index = map[int]int{
	MODE_OP1: 1,
	MODE_OP2: 2,
	MODE_OP3: 3,
	MODE_OP4: 4,
	MODE_OP5: 5,
	MODE_OP6: 6,
}

var mode_func = map[int]string{
	MODE_OP1: "",
	MODE_OP2: "xdp_op2_dummy_packet",
	MODE_OP3: "",
	MODE_OP4: "xdp_op4_random_drop",
	MODE_OP5: "xdp_op5_partial_upload",
	MODE_OP6: "",
}

func IndexOf[T comparable](collection []T, el T) int {
	for i, x := range collection {
		if x == el {
			return i
		}
	}
	return -1
}

// https://github.com/Gui774ume/krie/blob/master/pkg/krie/events/events.go#L37
// https://github.com/Gui774ume/krie/blob/master/pkg/krie/manager.go
// https://github.com/DataDog/ebpf-manager/blob/main/examples/program_router/main.go

func InitManagerOpt() manager.Options {
	return manager.Options{
		TailCallRouter: []manager.TailCallRoute{
			{
				ProgArrayName: "xdp_jump_table",
				Key:           uint32(1),
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "xdp_random_drop_func",
				},
			},
			{
				ProgArrayName: "xdp_jump_table",
				Key:           uint32(2),
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "xdp_partial_upload_func",
				},
			},
			{
				ProgArrayName: "xdp_jump_table",
				Key:           uint32(3),
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "xdp_dummy_packet_func",
				},
			},
		},
	}
}

func (es *eShuffler) loadEbpf() {

	// use single mode or use all
	es.addXDPProg()
	// es.addTestProg()

	es.editeBPFConstants()

	// load maps
	es.getMaps()
}

func (es *eShuffler) getMaps() error {
	var err error
	es.map_xdp_stats, _, err = es.manager.GetMap("xdp_action_stats")
	if err != nil {
		return fmt.Errorf("couldn't find maps/xdp_stats_map: %w", err)
	}

	es.map_deploy_mode, _, err = es.manager.GetMap("xdp_jump_table")
	if err != nil {
		return fmt.Errorf("couldn't find maps/xdp_prog_array: %w", err)
	} else {
		// tail.Update(uint32(1), uint32(2), 0)
		//fmt.Printf("tail: %v\n", tail)
	}

	return err
}

func (es *eShuffler) addTestProg() {
	var xdp_probe = &manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			EBPFFuncName: "ingress",
		},
		// ip a # second inf
		IfName: es.options.NetInf,
		// IfIndex:       2, // change this to the interface index connected to the internet
		XDPAttachMode: manager.XdpAttachModeSkb,
	}
	es.manager.Probes = append(es.manager.Probes, xdp_probe)
}

func (es *eShuffler) addXDPProg() {
	/*
		1. 如果开启多个算法就用tail call dispatch
		2. 否则只开启一种算法
	*/
	var mode = es.options.Mode
	logrus.Debugf("Current Mode: %b\n", mode)

	var use_ops = 0
	for mode_bit, op_name := range mode_func {
		if mode&mode_bit > 0 {
			use_ops++
			logrus.Debugf("\tenable operation: %v", op_name)
		}
	}

	if use_ops > 1 { // use tail call
		logrus.Infof("Use tail call")
		var probe = &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "xdp_dispatch",
			},
			// ip a # second inf
			IfName: es.options.NetInf,
			// IfIndex:       2, // change this to the interface index connected to the internet
			XDPAttachMode: manager.XdpAttachModeSkb,
		}

		var tail_calls = []manager.TailCallRoute{}
		for mode_bit, xdp_func := range mode_func {
			if xdp_func == "" {
				continue
			}
			if mode&mode_bit > 0 {
				var tail_call = manager.TailCallRoute{
					ProgArrayName: "xdp_jump_table",
					Key:           uint32(mode_index[mode_bit]),
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: xdp_func,
					},
				}
				logrus.Infof("Add tail call op: %s key: %d", xdp_func, mode_index[mode_bit])
				tail_calls = append(tail_calls, tail_call)
			}
		}

		es.manager.Probes = append(es.manager.Probes, probe)
		es.managerOptions.TailCallRouter = append(es.managerOptions.TailCallRouter, tail_calls...)
	} else {
		logrus.Infof("Install single XDP program to inf: %s", es.options.NetInf)
		for mode_bit, xdp_func := range mode_func {
			if mode&mode_bit > 0 {
				var xdp_probe = &manager.Probe{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: xdp_func,
					},
					// ip a # second inf
					IfName: es.options.NetInf,
					// IfIndex:       2, // change this to the interface index connected to the internet
					XDPAttachMode: manager.XdpAttachModeSkb,
				}
				es.manager.Probes = append(es.manager.Probes, xdp_probe)
				logrus.Infof("Install XDP: %s", xdp_func)
				break
			}
		}
	}
}

func (es *eShuffler) editeBPFConstants() {
	constants := []manager.ConstantEditor{
		{
			Name:  "opt_belta",
			Value: uint64(es.options.Beta * 100),
		},
	}
	es.managerOptions.ConstantEditors = append(es.managerOptions.ConstantEditors, constants...)
}
