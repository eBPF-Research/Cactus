package eshuffler

import "github.com/sirupsen/logrus"

func CHECK_ERR(err error, msg string) {
	if err != nil {
		logrus.Fatalf("Error Exit: %s! %v", msg, err)
	}
}
