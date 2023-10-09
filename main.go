package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/IrineSistiana/nsloc/app"
	_ "github.com/IrineSistiana/nsloc/app/preprocessing"
	_ "github.com/IrineSistiana/nsloc/app/scan"
	"github.com/IrineSistiana/nsloc/pkg/mlog"
	"go.uber.org/zap"
)

var (
	version = "dev/unknown"
)

var logger = mlog.L()

func main() {
	app.RootCmd.Version = version
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		sig := <-c
		logger.Warn("signal received", zap.Stringer("signal", sig))
		cancel()
	}()
	app.RootCmd.ExecuteContext(ctx)
}
