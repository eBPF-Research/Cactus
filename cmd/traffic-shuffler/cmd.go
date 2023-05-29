package main

import (
	"github.com/spf13/cobra"
)

var ConfFile string
var Verbose bool
var BasicConf = &cobra.Command{
	Use: "eShuffler",
}

func init() {
	BasicConf.Flags().StringVarP(&ConfFile, "file", "f", "", "Set yaml config file")
	BasicConf.MarkFlagRequired("file")
	BasicConf.Flags().BoolVarP(&Verbose, "verbose", "v", false, "Use verbose Log mode")
}
