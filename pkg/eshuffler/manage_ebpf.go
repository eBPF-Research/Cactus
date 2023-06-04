package eshuffler

import (
	_ "embed"
	"fmt"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"
)

//go:embed bin/bpf.o
var ProbeTC []byte

// https://github.com/Gui774ume/krie/blob/master/pkg/krie/events/events.go#L37
// https://github.com/Gui774ume/krie/blob/master/pkg/krie/manager.go
// https://github.com/DataDog/ebpf-manager/blob/main/examples/program_router/main.go

func (es *eShuffler) loadEbpf() {

	// use single mode or use all
	// es.addXDPProg()
	es.addTestProg()

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
	}

	es.map_op_stats, _, err = es.manager.GetMap("xdp_op_stats")
	if err != nil {
		return fmt.Errorf("couldn't find maps/xdp_op_stats: %w", err)
	}

	return err
}

func (es *eShuffler) addTestProg() {
	// var xdp_probe = &manager.Probe{
	// 	ProbeIdentificationPair: manager.ProbeIdentificationPair{
	// 		EBPFFuncName: "ingress",
	// 	},
	// 	// ip a # second inf
	// 	IfName: es.options.NetInf,
	// 	// IfIndex:       2, // change this to the interface index connected to the internet
	// 	XDPAttachMode: manager.XdpAttachModeSkb,
	// }

	var tc_probe = &manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			EBPFFuncName: "dummy_seq",
		},
		IfName:           es.options.NetInf,
		NetworkDirection: manager.Ingress,
	}
	// es.manager.Probes = append(es.manager.Probes, xdp_probe)
	es.manager.Probes = append(es.manager.Probes, tc_probe)
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
	op_num, op_mode := es.options.GetMode()
	constants := []manager.ConstantEditor{
		{
			Name:  "opt_alpha",
			Value: uint64(es.options.Alpha * 100),
		},
	}
	// 只启用一种算法，用于评测
	if op_num == 1 {
		op_index := mode_index[op_mode]
		constants = append(constants, manager.ConstantEditor{
			Name:  "one_op",
			Value: uint64(op_index),
		})
		logrus.Infof("Only use one op: %d", op_index)
	}
	es.managerOptions.ConstantEditors = append(es.managerOptions.ConstantEditors, constants...)
}
