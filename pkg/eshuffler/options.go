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
	NetInf string `yaml:"net_inf"`
	// InfIndex int    `yaml:"inf_index"` // 填网卡名字就行

	Alpha float32 `yaml:"alpha"`
	// Beta  float32 `yaml:"beta"`
}

const (
	MODE_OP1 = 0b1
	MODE_OP2 = 0b10
	MODE_OP3 = 0b100
	MODE_OP4 = 0b1000
)

var mode_index = map[int]int{
	MODE_OP1: 1,
	MODE_OP2: 2,
	MODE_OP3: 3,
	MODE_OP4: 4,
}

var mode_func = map[int]string{
	MODE_OP1: "xdp_op1_dummy_packet",
	MODE_OP2: "", // packet fragment
	MODE_OP3: "xdp_op3_partial_upload",
	MODE_OP4: "", // xdp_op4_windows_size
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

	logrus.Infof("Use Options mode: %b Inf: %s α: %f", opt.Mode, opt.NetInf, opt.Alpha)
	return err
}

func (opt *ESOptions) GetMode() (int, int) {
	var mode = opt.Mode
	var use_ops = 0
	var first = 0
	for mode_bit := range mode_func {
		if mode&mode_bit > 0 {
			first = mode_bit
			use_ops++
		}
	}
	if use_ops == 1 {
		return use_ops, first
	}
	// all ops
	return use_ops, mode
}
