package main

import (
	es "eBPF-Traffic-Shuffler/pkg/eshuffler"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

func setupLogger() {
	if Verbose {
		logrus.SetLevel(logrus.TraceLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	// logrus.SetReportCaller(true)
	// logrus.SetFormatter(&logrus.TextFormatter{
	// 	DisableColors: true,
	// 	FullTimestamp: true,
	// })
}

func parseConf() es.ESOptions {
	// flag.StringVar(&ConfFile, "file", "", "Set config file path")
	// flag.StringVar(&ConfFile, "f", "", "Set config file path")
	// flag.Parse()

	BasicConf.Execute()

	if ConfFile == "" {
		logrus.Infoln("Usage: eShuffule -f conf.yaml")
		os.Exit(-1)
	}

	var esOption = es.ESOptions{}
	es.CHECK_ERR(esOption.ReadOption(ConfFile), "Failed to parse yaml conf")
	return esOption
}

func main() {
	esOption := parseConf()

	setupLogger()

	eShuffler, err := es.IniteShuffler(esOption)
	es.CHECK_ERR(err, "eShuller Init Failed!")

	logrus.Infoln("eShuffler is now running (Ctrl + C to stop)\n")
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTSTP,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	// signal.Notify(stopper, os.Kill, syscall.SIGKILL)

	waitForExit := func() {
		<-stopper
		eShuffler.Stop()
		logrus.Infoln("eShuffler Exit! Clean up eBPF programs!")
		os.Exit(0)
	}

	if Verbose {
		go waitForExit()

		// blocking
		es.DumpBPFLog()
	} else {
		waitForExit()
	}
}
