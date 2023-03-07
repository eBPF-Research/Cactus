package main

import (
	"eBPF-Traffic-Shuffler/pkg/ebpf"
	es "eBPF-Traffic-Shuffler/pkg/eshuffler"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

func setupLogger(lev uint32) {
	logrus.SetLevel(logrus.Level(lev))
	// logrus.SetReportCaller(true)
	// logrus.SetFormatter(&logrus.TextFormatter{
	// 	DisableColors: true,
	// 	FullTimestamp: true,
	// })
}

func main() {
	setupLogger(uint32(logrus.TraceLevel))

	eShuffler, err := es.IniteShuffler()
	es.CHECK_ERR(err, "eShuller Init Failed!")

	logrus.Infoln("eShuffler is now running (Ctrl + C to stop)\n")
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		eShuffler.Stop()
		logrus.Infoln("eShuffler Exit!-With Ctrl-C!")
		os.Exit(0)
	}()

	ebpf.DumpBPFLog()
}
