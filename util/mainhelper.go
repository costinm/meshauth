package util

import (
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/costinm/meshauth"
)

// Main helper provides boilerplate utilities for running a main()
// and loading initial config.

var startupTime = time.Now()


// FindConfig is a simple loader for a config file.
func FindConfig(base string, s string) []byte {
	return meshauth.FindConfig(base, s)
}


// Main config helper - base implementation for minimal deps CLI.
//
// Larger binaries should use viper - which provides support for:
// - ini, json, yaml, java properties
// - remote providers (with encryption) - built in etcd3, consul, firestore
func GetString(key string) string {
	return os.Getenv(key)
}

// MainEnd should be the last call in main(). The app is expected to get all the config
// from file or env variables - if the command line arguments are not empty: exec the remaining
// and wait to complete - else wait for a signal.
func MainEnd() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	var cmd string
	var argv []string

	posArgs := os.Args
	if len(posArgs) == 1 {
		for {
			sig := <-sigCh

			slog.Info("Exit", "sig", sig, "running", time.Since(startupTime))

			d := GetString("DRAIN_TIMEOUT")
			if d == "" {
				d = "1"
			}
			di, _ := strconv.Atoi(d)
			time.AfterFunc(time.Second*time.Duration(di), func() {
				os.Exit(0)
			})
			// Testing force exit timing
			// return
		}
	}

	// If it has extra args, exec the command
	if len(posArgs) > 2 {
		cmd, argv = posArgs[1], posArgs[2:]
	} else {
		cmd = posArgs[1]
	}
	c := exec.Command(cmd, argv...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Env = os.Environ()

	if err := c.Start(); err != nil {
		slog.Error("failed to start subprocess", "cmd", cmd, "args", argv, "err", err)
		os.Exit(c.ProcessState.ExitCode())
	}

	go func() {
		sig := <-sigCh
		if err := c.Process.Signal(sig); err != nil {
			log.Printf("failed to signal process: %v", err)
		}
	}()

	if err := c.Wait(); err != nil {
		if v, ok := err.(*exec.ExitError); ok {
			ec := v.ExitCode()
			os.Exit(ec)
		}
	}

}
