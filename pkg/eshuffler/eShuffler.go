package eshuffler

import (
	"bytes"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"
)

type eShuffler struct {
	manager        *manager.Manager
	managerOptions manager.Options

	map_deploy_mode *ebpf.Map
	map_xdp_stats   *ebpf.Map
	map_op_stats    *ebpf.Map

	options   ESOptions
	startTime time.Time
}

func NeweShuffler(esOpt ESOptions) (*eShuffler, error) {
	logrus.Debug("Loading eBPF")

	es := &eShuffler{
		managerOptions: manager.Options{},
		manager:        &manager.Manager{},
		options:        esOpt,
	}

	es.loadEbpf()

	if err := es.manager.InitWithOptions(bytes.NewReader(ProbeTC), es.managerOptions); err != nil {
		return nil, fmt.Errorf("couldn't init ebpf-manager: %w", err)
	}

	return es, nil
}

type bpfDataRec struct {
	Rx_packets uint64
	Rx_bytes   uint64
}

func (es *eShuffler) Start() error {

	// start the manager
	if err := es.manager.Start(); err != nil {
		return fmt.Errorf("couldn't start ebpf-manager: %w", err)
	}

	es.startTime = time.Now()

	es.getMaps()
	go es.mapLog()

	return nil
}

func (es *eShuffler) Stop() error {
	if err := es.manager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop ebpf-manager: %w", err)
	}

	return nil
}

func IniteShuffler(esOpt ESOptions) (*eShuffler, error) {
	es, err := NeweShuffler(esOpt)
	if err != nil {
		return nil, fmt.Errorf("couldn't creating eShuffler: %w", err)
	}

	err = es.Start()
	return es, err
}
