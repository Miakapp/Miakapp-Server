package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/Miakapp/Miakapp-Server/internal/relay"
)

func main() {
	os.Exit(run())
}

func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("Invalid relay configuration", "error", err)
		return 1
	}

	engine, err := relay.New(cfg, auth.RejectingVerifier{}, logger)
	if err != nil {
		logger.Error("Unable to initialize relay", "error", err)
		return 1
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       75 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	serveFailure := make(chan error, 1)
	go func() {
		logger.Info(
			"Miakapp relay preview is listening",
			"address",
			cfg.ListenAddress,
			"authentication",
			"reject_all_until_control_plane_contract",
		)
		serveFailure <- httpServer.ListenAndServe()
	}()

	signalContext, stopSignals := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stopSignals()

	exitCode := 0
	select {
	case <-signalContext.Done():
		logger.Info("Relay shutdown requested")
	case err = <-serveFailure:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Relay HTTP server failed", "error", err)
			exitCode = 1
		}
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelShutdown()
	if err = httpServer.Shutdown(shutdownContext); err != nil {
		logger.Error("Relay HTTP shutdown exceeded its deadline", "error", err)
		exitCode = 1
	}
	engine.Close()
	return exitCode
}
