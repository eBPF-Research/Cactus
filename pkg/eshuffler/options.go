package eshuffler

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type ESOptions struct {
	Mode int `yaml:"mode"`

	/* 测试单独的op的效果
	 */
	USE_OP int `yaml:"use_op"`

	// network interface
	NetInf string `yaml:"net_inf"`
	// InfIndex int    `yaml:"inf_index"` // 填网卡名字就行

	Alpha float32 `yaml:"alpha"`
	// Beta  float32 `yaml:"beta"`
}

const (
	MODE_ALL_OP    = 0
	MODE_SINGLE_OP = 1
)

const TC_TAIL_CALL_MAP = "tc_jump_table"

/*
和 tail_call_map/logs中的op编号保持一致
ebpf/operation/op_states.h:16
*/
var OP_LIST = []string{
	// no-op, use for statistic all ingress/degress packet number
	"",

	// op-1
	"tc_op1_1_dummy_egress", "tc_op1_2_dummy_seq_ingress",

	// op-2
	"tc_op2_split_egress",

	// op-3
	"xdp_op3_partial_upload",

	// op-4
	"tc_op4_wnd_size_egress",
}

func (opt *ESOptions) ValidatedOP() {
	if opt.Mode == MODE_SINGLE_OP {
		if opt.USE_OP < len(OP_LIST) && OP_LIST[opt.USE_OP] != "" {
			logrus.Fatalf("Unsupported OP: %d\n", opt.USE_OP)
		}
	}
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

	opt.ValidatedOP()

	logrus.Infof("Use Options mode: %b Inf: %s α: %f", opt.Mode, opt.NetInf, opt.Alpha)
	return err
}

func (opt *ESOptions) GetOpMode() (bool, int) {
	return opt.Mode == MODE_ALL_OP, opt.USE_OP
}
