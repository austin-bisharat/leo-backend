package log

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"os"
)

var logger = logrus.New()

func InitLog() {
	f, err := os.OpenFile("main_log.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("error opening file: %v", err)
	}
	fmt.Printf("Opened logging file\n")
	logger.Out = f
	logger.Out = os.Stderr
	logger.Debug("Start logging")
}

func Debug(s string) {
	fmt.Printf(s + "\n")
}
