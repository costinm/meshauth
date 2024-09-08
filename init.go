package meshauth

import (
	"context"
	"encoding/json"
	"expvar"
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

	"github.com/costinm/meshauth/pkg/apis/authn"
)

// Mesh initialization

// Module and expvar.
// To reduce dependencies and size, all module builders should be registered and retrieved from the expvar registry ( and
// possibly other places).



// Module is a component providing a specific functionality, similar to a
// .so file in traditional servers for mesh. In many cases it provides a listener
// or dialer or some other service.
//
// Usually a protocol implementation, callbacks, etc.
// This allows a 'modular monolith' approach and avoids deps.
// The Module is an instance of a module with a specific name and set of
// key/value settings.
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

func (m *Module) String() string {
	b, _ := json.Marshal(m)
	return string(b)
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

	AddKnownType[Module](name, func(ctx context.Context, namespace, name string) *Module {
		m := &Module{}
		m.Mesh = ContextValue[*Mesh](ctx, "mesh")

		// TODO: load config from the mesh config store or Mesh.Modules

		err := template(m)
		if err != nil {
			slog.Error("/ModInitError", "name", name, "err", err)
		}
		return m
	})
}

func (mesh *Mesh) initConfiguredModule(m *Module) error {
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

	m.Mesh = mesh

	err := f(m)

	RegisterMod[*Module](DefaultContext, protocol, "", m.Name, m)

	return err
}

// initModules will initialize all enabled components for this mesh.
// MeshConfig embeds a list of configs, of Module type - the actual object
// should be registered as AddKnownType to allow loading from config stores as well.
//
func (mesh *Mesh) initModules() error {
	for n, md := range mesh.Modules {
		err := mesh.initConfiguredModule(md)
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

	// TODO: load dynamic modules (from K8S, files)
	var err error
	ModSeq2[*Module](ctx, func(s string, md *Module) bool {
		if st, ok := md.Module.(Starter); ok {
			err = st.Start(ctx)
			if err != nil {
				log.Println("Failed to start", s, md, err)
				return false
			}
		}
		return true
	})

	//for _, md := range mesh.Modules {
	//	if st, ok := md.Module.(Starter); ok {
	//		err := st.Start(ctx)
	//		if err != nil {
	//			return err
	//		}
	//	}
	//}
	return err
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


// Configurations for the mesh. Besides 'mesh identity' and authn/authz, dynamic config is a main feature of the
// mesh.
//
// - JSON files in a base directory - this is included in this package.
// - HTTP with mesh auth - TODO
// - Yaml files - require adding a yaml parser ( and dependency )
// - K8S or other plugins
// - XDS - plugin.


// FindConfig is a simple loader for a config file.
func FindConfig(base string, out interface{}) error {
	err := findConfigBase(base, out)
	if err != nil {
		return err
	}

	// Quick hack to load environment variables into the config struct.

	// mapstructure package can also convert generic maps to structs - this is just minimal

	envl := os.Environ()
	envm := map[string]string{}
	for _, k := range envl {
		kv := strings.SplitN(k, "=", 2)
		if len(kv) == 2 {
			if strings.HasPrefix(kv[0], base) {
				key := strings.TrimPrefix(kv[0], base)
				envm[key] = kv[1]
			}
		}
	}
	envb, err := json.Marshal(envm)
	if err != nil {
		log.Println("Failed to overlay env", envl, err, envb)
		return err
	}

	return json.Unmarshal(envb, out)
}

func findConfigBase(base string, out interface{}) error {
	var data []byte =  nil

	fb, err := os.ReadFile("./" + base + ".json")
	if err == nil {
		data = fb
	} else {
		fb, err = os.ReadFile("/" + base + "/" + base + ".json")
		if err == nil {
			data = fb
		}
	}

	if data != nil {
		err = json.Unmarshal(data, out)
		if err != nil {
			return err
		}
		return nil
	}

	if yu, ok := expvar.Get("/unmarshaller/yaml").(Unmarshaller); ok {
		fb, err := os.ReadFile("./" + base + ".yaml")
		if err == nil {
			data = fb
		} else {
			fb, err = os.ReadFile("/" + base + "/" + base + ".yaml")
			if err == nil {
				data = fb
			}
		}
		if data != nil {
			err = yu.Unmarshal(data, out)
			if err != nil {
				return err
			}
			return nil
		}
		basecfg := os.Getenv(base)
		if basecfg != "" {
			data = []byte(basecfg)
			err = yu.Unmarshal(data, out)
			if err != nil {
				return err
			}
			return nil
		}
	}

	basecfg := os.Getenv(base)
	if basecfg != "" {
		data = []byte(basecfg)
		err = json.Unmarshal(data, out)
		if err != nil {
			return err
		}
		return nil
	}


	return nil
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
	FindConfig(base, cfg)

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
