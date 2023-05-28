package ebpf

import (
	_ "embed"

	manager "github.com/DataDog/ebpf-manager"
)

//go:embed bin/bpf.o
var ProbeTC []byte

// https://github.com/Gui774ume/krie/blob/master/pkg/krie/manager.go
// https://github.com/DataDog/ebpf-manager/blob/main/examples/program_router/main.go

func InitManagerOpt() manager.Options {
	return manager.Options{}

}

func InitManager() *manager.Manager {
	return &manager.Manager{
		Probes: []*manager.Probe{
			// { // tc/classifier/one
			// 	ProbeIdentificationPair: manager.ProbeIdentificationPair{
			// 		EBPFFuncName: "one",
			// 	},
			// 	IfName:           "lo", // change this to the interface index connected to the internet
			// 	NetworkDirection: manager.Egress,
			// },
			{ // tc/classifier/ingress_redirect
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "ingress_redirect",
				},
				IfIndex: 7,
				// IfName:           "lo", // change this to the interface index connected to the internet
				NetworkDirection: manager.Egress,
			},
			// {
			// 	ProbeIdentificationPair: manager.ProbeIdentificationPair{
			// 		EBPFFuncName: "ingress",
			// 	},
			// 	// ip a # second inf
			// 	IfName: "eth0",
			// 	// IfIndex:       2, // change this to the interface index connected to the internet
			// 	XDPAttachMode: manager.XdpAttachModeSkb,
			// },
		},
	}
}
