package appinit

import (
	"encoding/json"
	"expvar"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Loading app data from environment vars and directories.
//
// Using environment variables is convenient for containers and scripts, but
// it is not very flexible for servers, the config is read only. Config files
// located in config maps, Secrets (for K8S) or remote servers (as resources)
// is flexible and allow dynamic (some) changes without restart.
//
// K8S 'resource + events' model is far more dynamic, but requires a
// 'resource server' or filesystem combined with 'pubsub' like notifications.
//
// This file allows detecting the environment - including 'well known' files,
// and it is intended only for the 'main' application. It also has a helper to
// exec a child app and wait for completion.
//
// We're looking for:
// - private key (.ssh/id_ecdsa) or istio-style or ./id_ecdsa (certs package)
// - kubeconfig file
// - a google or OAuth file
// - overrides for the 'work dir' (cache, generated files) and root config.
// - hostname, fqdn, detecting CloudRun and mesh.

type Env struct {
	// Parsed environment variables.
	Env map[string]string

	// Local writable directory where configs can be cached and
	// generated files can be written.
	WorkDir string

	// Root directory or URL for config files.
	ConfigDir string

	// Hostname and primary FQDN.
	Hostname string
	FQDN     string
}

// TODO: use sync.Once
var defaultResStore = NewResourceStore().defaults()

// AppResourceStore returns the default, per app resource store.
// It is using current dir as root for the configs and for saving.
// Should NOT be used in tests - use NewResourceStore instead.
func AppResourceStore() *ResourceStore {
	return defaultResStore
}

func (a *ResourceStore) patchEnv(base string, out any) error {
	// Quick hack to load environment variables into the config struct.

	// mapstructure package can also convert generic maps to structs - this is just minimal

	// TODO: move to resource loading. Only if base is set (i.e. not for ephemeral)
	envl := os.Environ()

	var envb []byte
	var err error
	envs := a.Env[base]
	if envs == "" {
		envm := map[string]string{}
		for k, v := range a.Env {
			if k == base {

			}
			if strings.HasPrefix(k, base) {
				key := strings.TrimPrefix(k, base)
				envm[key] = v
			}
		}

		envb, err = json.Marshal(envm)
		if err != nil {
			log.Println("Failed to overlay env", envl, err, envb)
			return err
		}
	} else {
		envb = []byte(envs)
	}

	return unmarshal(envb, out)
}

const ROOT = "mesh"

// defaults load opinionated application defaults:
// - current dir for configs and cache/saved data
// - env vars can override configs - including base
func (a *ResourceStore) defaults() *ResourceStore {
	for _, v := range os.Environ() {
		kv := strings.SplitN(v, "=", 2)
		if len(kv) == 2 {
			a.Env[kv[0]] = kv[1]
		}
	}
	base := os.Getenv("MESH_CFG")
	if base == "" {
		base = "."
	}
	a.BaseDir = base

	a.FS = os.DirFS(base)

	expvar.Publish(ROOT, a)
	return a
}

// WaitEnd should be the last thing in a main() app - will block, waiting for SIGTERM and handle draining.
//
// This will also handle any extra args - interpreting them as a CLI and running the command, allowing
// chaining in docker. Init is using a yaml for config and no CLI.
func WaitEnd() {

	if len(os.Args) == 1 {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		for {
			// An alternative is to handle the stdin, as
			// a communication channel with parent for server apps.
			// Perhaps with a flag.
			sig := <-sigCh

			d := os.Getenv("DRAIN_TIMEOUT")
			if d == "" {
				d = "1000"
			}
			di, _ := strconv.Atoi(d)

			slog.Info("Exit", "sig", sig, "running", time.Since(startupTime),
				"drain", di)

			defaultResStore.Close()
			time.AfterFunc(time.Millisecond*time.Duration(di), func() {
				os.Exit(0)
			})
		}
	}

	cmd := os.Args[1]
	var argv []string

	// If it has extra args, exec the command
	if len(os.Args) > 2 {
		argv = os.Args[2:]
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

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
