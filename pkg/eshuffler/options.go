package eshuffler

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type ESOptions struct {
	Mode int `yaml:"mode"`

	// network interface
	NetInf   string `yaml:"net_inf"`
	InfIndex int    `yaml:"inf_index"`

	Alpha float32 `yaml:"alpha"`
	Beta  float32 `yaml:"beta"`
}

func (opt *ESOptions) ReadOption(fi string) error {
	f, err := os.Open(fi)
	if err != nil {
		return fmt.Errorf("couldn't load config file %s: %w", fi, err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)

	if err = decoder.Decode(opt); err != nil {
		return fmt.Errorf("couldn't decode config file %s: %w", fi, err)
	}

	logrus.Infof("Use Options mode: %b Inf: %s α: %f β: %f", opt.Mode, opt.NetInf, opt.Alpha, opt.Beta)
	return err
}
