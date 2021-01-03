package main

import (
	"sync"

	server "github.com/softcorp-io/hqs-user-service/server"
	"go.uber.org/zap"
)

func main() {
	var wg sync.WaitGroup
	logger, _ := zap.NewProduction()

	server.Init(logger)

	wg.Add(1)
	server.Run(logger, &wg)
}
