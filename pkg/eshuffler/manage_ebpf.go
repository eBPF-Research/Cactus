package eshuffler

import (
	_ "embed"
	"fmt"
	"strings"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"
)

//go:embed bin/bpf.o
var ProbeTC []byte

// https://github.com/Gui774ume/krie/blob/master/pkg/krie/events/events.go#L37
// https://github.com/Gui774ume/krie/blob/master/pkg/krie/manager.go
// https://github.com/DataDog/ebpf-manager/blob/main/examples/program_router/main.go

func (es *eShuffler) loadEbpf() {

	// use all op or use single op
	es.addEShuffleOps()

	// only for development
	// es.addTestProg()

	// modify bpf bytecode to add some constants
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

	es.map_deploy_mode, _, err = es.manager.GetMap("es_jump_table")
	if err != nil {
		return fmt.Errorf("couldn't find maps/es_jump_table: %w", err)
	}

	es.map_op_stats, _, err = es.manager.GetMap("es_op_stats")
	if err != nil {
		return fmt.Errorf("couldn't find maps/es_op_stats: %w", err)
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
			EBPFFuncName: "wnd_size",
		},
		IfName:           es.options.NetInf,
		NetworkDirection: manager.Egress,
	}
	// es.manager.Probes = append(es.manager.Probes, xdp_probe)
	es.manager.Probes = append(es.manager.Probes, tc_probe)
}

func (es *eShuffler) addEShuffleOps() {

	use_all_op, used_op := es.options.GetOpMode()

	if use_all_op {
		logrus.Debugf("Current Mode Use All OPs")

		// install ingress/egress program
		es.addProgByName("tc_dispatch_ingress")

		es.addProgByName("tc_dispatch_egress")

		// 由于暂时只用一个tc的tail call map，所以xdp直接加载
		// es.addProgByName("xdp_dispatch")
		es.addProgByName("xdp_op3_partial_upload")

		// install tail calls
		for idx, op_name := range OP_LIST {
			if strings.HasPrefix(op_name, "tc_") {
				es.addTailCallProg(TC_TAIL_CALL_MAP, op_name, idx)
			}
		}

	} else {
		logrus.Debugf("Current Mode Single-OP: %d\n", used_op)

		var op_func_name = OP_LIST[used_op]
		es.addProgByName(op_func_name)
	}
}

func (es *eShuffler) addProgByName(prog_name string) {
	var probe *manager.Probe = nil

	if strings.HasPrefix(prog_name, "xdp_") {
		probe = &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: prog_name,
			},
			// ip a # second inf
			IfName: es.options.NetInf,
			// IfIndex:       2, // change this to the interface index connected to the internet
			XDPAttachMode: manager.XdpAttachModeSkb,
		}
	}

	if strings.HasPrefix(prog_name, "tc_") {

		var net_dir = manager.Ingress
		if strings.HasSuffix(prog_name, "_egress") {
			net_dir = manager.Egress
		}

		probe = &manager.Probe{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: prog_name,
			},
			IfName:           es.options.NetInf,
			NetworkDirection: net_dir,
		}

	}

	if probe != nil {
		logrus.Debug("\tInstall Prog: ", prog_name)
		es.manager.Probes = append(es.manager.Probes, probe)
	}
}

func (es *eShuffler) addTailCallProg(jump_table string, prog_name string, key int) {
	var tail_call = manager.TailCallRoute{
		ProgArrayName: jump_table,
		Key:           uint32(key),
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			EBPFFuncName: prog_name,
		},
	}
	logrus.Infof("\tAdd tail call op: %s key: %d", prog_name, key)
	es.managerOptions.TailCallRouter = append(es.managerOptions.TailCallRouter, tail_call)
}

func (es *eShuffler) editeBPFConstants() {
	use_all_op, used_op := es.options.GetOpMode()
	constants := []manager.ConstantEditor{
		{
			Name:  "opt_alpha",
			Value: uint64(es.options.Alpha * 100),
		},
	}
	// 只启用一种算法，用于评测
	if !use_all_op {
		constants = append(constants, manager.ConstantEditor{
			Name:  "one_op",
			Value: uint64(used_op),
		})
		logrus.Infof("Only use one op: %d", used_op)
	}
	es.managerOptions.ConstantEditors = append(es.managerOptions.ConstantEditors, constants...)
}
