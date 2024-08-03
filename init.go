package meshauth

import (
	"context"
	"errors"
	"github.com/costinm/meshauth/pkg/apis/authn"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Mesh initialization


// Module is a component providing a specific functionality, similar to a
// .so file in traditional servers. In many cases it provides a listener
// or dialer or some other service.
//
// Usually a protocol implementation, callbacks, etc.
// This allows a 'modular monolith' approach and avoids deps.
// The Module is an instance of a module with a specific name and set of
// key/value settings.
//
// TODO: why not support .so files and dynamic load ?
type Module struct {
	Name string `json:"name"`

	// A module may use an address to initialize - should be host:port (go style),
	// or a URL. Semantic specific to the module - can be the default listen address
	// or an address to connect to. This is a common setting so keeping it top level.
	Address string `json:"address,omitempty"`


	// TODO: rename to 'remoteAddress' or 'dest' - use to indicate an address to use as client
	ForwardTo string `json:"forwardTo,omitempty"`

	// Internal state.
	NetListener net.Listener `json:"-"`

	// Mux is the main server mux, for L7 modules.
	Mux http.ServeMux `json:"-"`

	// Env variables - not meant to be used as a real config, but better than direct use of os.Getenv
	// Getenv may check os env variables too.
	Env    map[string]string `json:"env,omitempty"`

	Mesh   *Mesh `json:"-"`

	// The module native interface.
	Module interface{} `json:"-"`

}

type Starter interface {
	Start(ctx context.Context) error
}
type Closer interface {
	Close() error
}

func (m Module) GetPort(dp int32) int32 {
	if m.Address == "" {
		return dp
	}
	_, p, err := net.SplitHostPort(m.Address)
	if err != nil {
		return dp
	}
	pp, err := strconv.Atoi(p)
	if err != nil {
		return dp
	}
	return int32(pp)

}

var modInit = map[string]func(*Module) error{}

// Caddy is using a RegisterModule(Module) in init(), with the interface
// returning a ModuleInfo struct with the New() and a namespaced ID.
// The module may implement different interfaces - like TokenSource,
// ContextDialler, etc. The naming is a bit confusing - Module.CaddyModule().New returns a
// Module. ModuleMap has the config with json.RawMessage

// In K8S, each 'CRD' defines an equivalent module - with a spec and marshall
// mechanisms for loading config.


// Register will register a Module initializer function for a kind of modules, allowing conditional compilation
// and keeping dependencies separated.
//
// It should be called from small wrappers with conditional compilation tags
// or from main(). The actual implementation should be in a separate package.
func Register(name string, template func(*Module) error) {
	modInit[name] = template
}

func (mesh *Mesh) AddModule(m *Module) error {
	return mesh.addModule(m, true)
}
func (mesh *Mesh) addModule(m *Module, started bool) error {
	parts := strings.Split(m.Name, "-")
	protocol := parts[0]

	if m.Address == "" {
		if len(parts) == 2 {
			m.Address = ":" + parts[1]
		} else if len(parts) > 2 {
			m.Address = net.JoinHostPort(parts[1], parts[2])
		}
	}

	f := modInit[protocol]

	if f == nil {
		return errors.New("Not found " + m.Name)
	}
	m.Mesh = mesh
	err := f(m)

	if started {
		if st, ok := m.Module.(Starter); ok {
			err = st.Start(context.Background())
			if err != nil {
				return err
			}
		}
	}
	return err
}

// initModules will initialize all enabled components for this mesh.
//
func (mesh *Mesh) initModules() error {
	for n, md := range mesh.Modules {
		err := mesh.addModule(md, false)
		if err != nil {
			slog.Warn("ModuleInit", "name", md.Name, "err", err, "n", n)
		} else {
			//slog.Info("Module", "name", md.Name, "addr", md.Address)
		}
	}
	return nil
}

func (mesh *Mesh) Start(ctx context.Context) error {

	mesh.initModules()

	for _, md := range mesh.Modules {
		if st, ok := md.Module.(Starter); ok {
			err := st.Start(ctx)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (mesh *Mesh) Close(ctx context.Context) error {
	for _, md := range mesh.Modules {
		if st, ok := md.Module.(Closer); ok {
			err := st.Close()
			if err != nil {
				slog.Info("CloseError", "name", md.Name, "err", err)
			}
		}
		if md.NetListener != nil {
			md.NetListener.Close()
		}
	}
	return nil
}

var startupTime = time.Now()

func (mesh *Mesh) MainEnd() {

	if len(os.Args) == 1 {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		for {
			sig := <-sigCh


			d := os.Getenv("DRAIN_TIMEOUT")
			if d == "" {
				d = "1000"
			}
			di, _ := strconv.Atoi(d)

			slog.Info("Exit", "sig", sig, "running", time.Since(startupTime),
				"drain", di)

			mesh.Close(context.Background())
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

// FromEnv will attempt to identify and Init the certificates.
// This should be called from main() and for normal app use.
//
// New can be used in tests or for fine control over
// what cert is loaded.
//
// - default GKE/Istio location for workload identity
// - /var/run/secrets/...FindC
// - /etc/istio/certs
// - $HOME/.ssh/id_ecdsa - if it is in standard pem format
//
// ssh-keygen -t ecdsa -b 256 -m PEM -f id_ecdsa
//
//
// If a cert is found, the identity is extracted from the cert. The
// platform is expected to refresh the cert.
//
// If a cert is not found, Cert field will be nil, and the app should
// use one of the methods of getting a cert or call InitSelfSigned.
func FromEnv(ctx context.Context, cfg *MeshCfg, base string) (*Mesh, error) {
	ma := New(cfg)
	err := ma.FromEnv(ctx, base)

	return ma, err
}

type InitFromEnv interface {
	FromEnv(ctx context.Context, base string) error
}

// FromEnv will initialize Mesh using local files and env variables.
//
func (mesh *Mesh) FromEnv(ctx context.Context, base string) (error) {

	cfg := mesh.MeshCfg

	// Detect cloudrun
	ks := os.Getenv("K_SERVICE")
	if ks != "" {
		sn := ks
		verNsName := strings.SplitN(ks, "--", 2)
		if len(verNsName) > 1 {
			sn = verNsName[1]
		}
		mesh.Name = sn
		mesh.AuthnConfig.Issuers = append(mesh.AuthnConfig.Issuers,
			&authn.TrustConfig{
				Issuer: "https://accounts.google.com",
			})
	}

	// Determine the workload name, using environment variables or hostname.
	// This should be unique, typically pod-xxx-yyy

	// Merge a found config and env variables.
	mesh.Get(base, cfg)

	if mesh.Name == "" {
		name := os.Getenv("POD_NAME")
		if name == "" {
			name = os.Getenv("WORKLOAD_NAME")
		}
		mesh.Name = name
	}

	if mesh.Name == "" {
		name, _ := os.Hostname()
		if strings.Contains(name, ".") {
			parts := strings.SplitN(name, ".", 2)
			mesh.Name = parts[0]
			if mesh.Domain == "" {
				mesh.Domain = parts[1]
			}
		} else {
			mesh.Name = name
		}
	}

	if mesh.Domain == "" {
		mesh.Domain = "mesh.internal"
	}


	// Attempt to locate existing workload certs from the cert dir.
	// TODO: attempt to get certs from an agent.
	if mesh.Cert == nil {
		if cfg.ConfigLocation == "-" {
			return nil
		}
		certDir := cfg.ConfigLocation
		if certDir == "" {
			// Try to find the 'default' certificate directory
			if _, err := os.Stat(filepath.Join("./", tlsKey)); !os.IsNotExist(err) {
				certDir = "./"
			} else if _, err := os.Stat(filepath.Join(varRunSecretsWorkloadSpiffeCredentials, tlsKey)); !os.IsNotExist(err) {
				certDir = varRunSecretsWorkloadSpiffeCredentials
			} else if _, err := os.Stat(filepath.Join("/var/run/secrets/istio", "key.pem")); !os.IsNotExist(err) {
				certDir = "/var/run/secrets/istio/"
			} else if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".ssh", tlsKey)); !os.IsNotExist(err) {
				certDir = filepath.Join(os.Getenv("HOME"), ".ssh")
			}
		}

		if certDir != "" {
			return mesh.initFromDirPeriodic(certDir, true)
		}
	}

	return nil
}
