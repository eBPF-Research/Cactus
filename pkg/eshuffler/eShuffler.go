package eshuffler

import (
	"bytes"
	"eBPF-Traffic-Shuffler/pkg/ebpf"
	"fmt"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/sirupsen/logrus"
)

type eShuffler struct {
	manager        *manager.Manager
	managerOptions manager.Options

	mode      int
	startTime time.Time
}

func NeweShuffler() (*eShuffler, error) {
	logrus.Debug("Loading eBPF")

	es := &eShuffler{
		managerOptions: ebpf.InitManagerOpt(),
		manager:        ebpf.InitManager(),
	}

	if err := es.manager.Init(bytes.NewReader(ebpf.ProbeTC)); err != nil {
		return nil, fmt.Errorf("couldn't init ebpf-manager: %w", err)
	}

	return es, nil
}

func (es *eShuffler) Start() error {

	// start the manager
	if err := es.manager.Start(); err != nil {
		return fmt.Errorf("couldn't start ebpf-manager: %w", err)
	}

	es.startTime = time.Now()

	return nil
}

func (es *eShuffler) Stop() error {
	if err := es.manager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop ebpf-manager: %w", err)
	}

	return nil
}

func IniteShuffler() (*eShuffler, error) {
	es, err := NeweShuffler()
	if err != nil {
		return nil, fmt.Errorf("couldn't creating eShuffler: %w", err)
	}

	err = es.Start()
	return es, err
}
