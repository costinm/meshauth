package appinit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"plugin"
	"reflect"
	"time"
)

// Generic initialization code. There are many ways to
// bootstrap an app with configuration, but a common pattern to
// allow modularity is to have some registry of functions that
// perform creation or initialization of each module.

// The ResourceStore is an abstraction around fs.FS - where each file is
// mapped to a Resource and unmarshalled automatically.
//

// A Resource contains data and should be serializable to JSON (and
//  other formats)
// It can implement methods - or be associated with methods with signature
// func(ctx, resource) (response,error)
//
// The resource can be remote - identified by a URL or path. It is loaded
// on-demand. Methods can be executed remotely ( path:METHOD ).

// Caddy: 'ModuleInfo' is like a Class with name and New. Object also has a 'get class'
//      CaddyModule, and is first loaded with config (json.Unmarshal) than used depending
//      on provided interfaces and kind. A 'apiversion + kind' style is used.
//      Problem: convenience of import 'init()' comes with a strong dep on caddy.
//      caddy.RegisterModule(Module) in init() is fine in caddy-specific adapters
//     The naming is a bit confusing - Module.CaddyModule().New returns a
//     Module. ModuleMap has the config with json.RawMessage

//
// K8S: pure configs types, registered in a (complex) 'registry' object.
//      'controllers' operate on configs, can load any config object by type+name and
//      handle changed configs.
//      Problem: heavy deps and complex
//      Benefit: controllers can operate on any configs, decoupled.
// In K8S, each 'CRD' defines an equivalent module - with a spec and marshall
// mechanisms for loading config.
//
//
// Current (v4) approach:
// - pure configs (like K8S), in a 'filesystem' like registry.
// - 'controllers' operate on configs, can load any config object by type+name and
//   handle changed configs. Have a pure New()-like method to initialize defaults.
// - optional Start(ctx), Init(ctx) - will load and may watch for config changes, can operate
//   on any config object. Pure configs don't have 'start'.
//
// For the config objects - should be possible to 'pull' from k8s, gRPC, caddy registries
// and reuse the objects. Also to treat the data as map[string]any.
//
//

// Instead of registering modules with a dependency to this package, it
// is possible to use the expvar package as a registry.
//
// Code (builders) should use a naming pattern - prefix like mod.github.com/foo
// It requires implementing the String interface and New.
//
// Other sources of builders are the gRPC and K8S registries.

// Value is a typed helper for getting a resource.
func Value[T any](ctx context.Context, key any) *T {
	// WIP: get the context store
	v := ctx.Value(key)
	if vt, ok := v.(T); ok {
		return &vt
	}
	return nil
}

// Get is a typed getter, wraps rs.Get()
func Get[T any](ctx context.Context, rs *ResourceStore, key string) (*T, error) {
	// WIP: get the context store
	v, err := rs.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if vt, ok := v.(*T); ok {
		return vt, nil
	}
	return nil, nil
}

// Interfaces used by resource store

type StarterContext interface {
	Start(ctx context.Context) error
}

type Starter interface {
	Start() error
}

// Provisioner is called after unmarshal, before start. It allows to
// set dependencies and do other initialization. Should not start running
// anything.
//
// ctx may be used to get Values - which can be dynamic.
type Provisioner interface {
	Provision(ctx context.Context) error
}

type ObjInitializer interface {
	NewInstance(ctx context.Context) (any, error)
}

// Initializer is using an explicit function to get other modules.
// Alternative to Provisioner.
type Initializer interface {
	Init(ctx context.Context, resGet func(ctx2 context.Context, name string) any) error
}

type Saver interface {
	// Save will save the resource to an address. If empty, the same address
	// that was used for loading will be used or the default address.
	// This handles both update and create.
	Save(ctx context.Context, addr string) error
}

type Closer interface {
	Close() error
}

// ResourceHolder is like a dir, for named resources.
// The name should be relative path, with "/" as delimiter.
type ResourceHolder interface {
	Resource(ctx context.Context, name string) (any, error)
}

// a module can also be implemented in a library (.so file, WASM or
// similar) that will be loaded. Otherwise the main() or some
// imported code should have registered a module 'new' function
// that can create the Module.

// TODO: dynamic modules (.so)
// Using plugin.Open()
// will run the init() - so can self-register the module
// or Lookup(name) -> returns Any for a function or variable.

// Benefit: smaller binary and runtime size for main, only load
// a module if needed (the init() can do a lot of crap)
// With proper naming (directory using version and flags) it can
// allow post-build install of modules.

// go build -buildmode=plugin

// plugin can also have a main() and should be able to start a
// http or gRPC or flatbuffer-based server.

// TODO: non-go modules (.so)
//    #[no_mangle]
//   pub extern "C" fn add(x: i32, y: i32) -> i32 {
//       x + y
//   }
// rustc --crate-type=cdylib mylib.rs -o libmylib.so

// purego: Dlopen, RegisterLibFunc

// WASM
// - wazero - zero deps

// Class is pretty much like a Java class - it has a New() method creating an
// object.
//type Class[T any] interface {
//	New() T
//}
//
//type TModule[T any] struct {
//	T T
//
//}

// There are 2 'styles', both valid:
// - a controller that loads/watches configs once started.
// - a handler that is called with a data object and is processing that instance.
//   This has variations - rpc style (in data, out data), http handler, or 'long-running'
//   modules that get a config object injected (in New or SetConfig), or embeds the config.

// Implements the fs.FS interface.
func (rs *ResourceStore) Open(name string) (fs.File, error) {
	// Name is a relative path. The resource Name() should return
	// the 'base name' without "/"
	f, err := rs.GetResource(name)

	return &ResourceFile{Resource: f}, err
}

func (rs *ResourceStore) ReadFile(name string) ([]byte, error) {
	f, err := rs.GetResource(name)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, ErrNotFound
	}
	return f.Spec, nil
}

var ErrNotFound = errors.New("not found")

func (a *ResourceStore) String() string {
	ab, _ := json.Marshal(a)
	return string(ab)
}

// NewResourceStore creates a new resource store, using a FS interface
// for reading configs and a local dir for cache and saving.
func NewResourceStore() *ResourceStore {
	return &ResourceStore{
		loaded: make(map[string]*Resource),
		Env:    make(map[string]string),
		Logger: slog.Default(),
	}
}

func (rs *ResourceStore) Load(ctx context.Context, base fs.FS, local string) error {
	rs.BaseDir = local
	rs.FS = base

	// Something called app.json or app.yaml - may be remote
	cfg, err := rs.GetResource("app")
	if err != nil {
		return err
	}
	if cfg == nil {
		// Not an error to not find the default config
		return nil
	}
	// The raw object is the resource store itself.
	cfg.raw = rs

	return cfg.Provision(ctx, rs, rs)
}

// For each stored configuration, load the object if a new() function exists.
//
// Named using Caddy conventions (playing with it, as good name as any)
func (a *ResourceStore) Provision(ctx context.Context) error {
	a.appCtx = ctx // May be a caddy.Context

	a.loaded = map[string]*Resource{}

	for _, n := range a.Services {
		obj, err := a.GetResource(n)
		if err != nil {
			return err
		}
		if obj == nil {
			fmt.Println("Missing object ", n, err)
			continue
		}
		err = obj.Init(ctx, a)
		if err != nil {
			return err
		}
		a.loaded[n] = obj
	}

	//// Save the objects.
	//for _, cfg := range a.Data {
	//	a.loaded[cfg.BaseName] = cfg
	//}
	//
	//for _, cfg := range a.Data {
	//	// new + unmarshall
	//	err := cfg.Init(ctx, a)
	//	if err != nil {
	//		return err
	//	}
	//}
	//
	//for _, cfg := range a.Data {
	//	if cfg.raw == nil {
	//		continue
	//	}
	//
	//}

	return nil
}

// Set adds a value to the in-memory resource map. It will be wrapped in a Resource, but doesn't have serialization
// state.
//
// Values can be injected or used as a registry.
//
// Few pre-defined names are used:
//   - json/yaml2json - a function that converts yaml to json
//   - json/unmarshaller - a	function	that		unmarshals
func (a *ResourceStore) Set(name string, val any) *Resource {
	r := &Resource{raw: val, BaseName: name}
	a.loaded[name] = r
	return r
}

func (a *ResourceStore) SetResource(n string, c *Resource) {
	a.loaded[n] = c
}

// Get returns a resource object by name.
// The name consists of Kind/Name, e.g. "ConfigMap/foo", or only Kind.
//
// If a file or resource with the given name is found - it will be unmarshalled into the object.
// The result is NOT saved into the 'loaded' objects.
func (a *ResourceStore) Get(ctx context.Context, name string) (any, error) {

	cfg, err := a.GetResource(name)
	if err != nil {
		return nil, err
	}

	if cfg != nil && cfg.raw != nil {
		return cfg.raw, nil
	}

	if cfg == nil {
		cfg = &Resource{BaseName: name}
	}

	err = cfg.Init(ctx, a)
	if err != nil {
		return nil, err
	}
	return cfg.raw, nil
}

// Init will initialize the resource by unmarshalling the 'spec' and calling Provisioner and other optional
// interfaces.
func (cfg *Resource) Init(ctx context.Context, a *ResourceStore) error {
	if cfg.raw != nil {
		return nil
	}
	if o := appCodec.New(cfg.BaseName); o != nil {
		return cfg.Provision(ctx, a, o)
		// TODO: look for an 'type to object' function - for types that don't implement NewInstance
	}
	// 'raw' config, not a problem.
	return nil // NewSlogError("MissingNew", "name", cfg.Name)
}

func (cfg *Resource) Provision(ctx context.Context, a *ResourceStore, o any) error {

	o, err := appCodec.InitObject(ctx, o, cfg.Spec)
	if err != nil {
		return NewSlogError("Resource.Init.Unmarshal", "err", err, "name", cfg.BaseName)
	}

	err = a.resolveRef(ctx, cfg, a)
	if err != nil {
		return err
	}

	if wrs, ok := o.(WithResourceStorer); ok {
		wrs.WithResourceStore(a)
	}

	if onew, ok := o.(Provisioner); ok {
		err := onew.Provision(ctx)
		if err != nil {
			return err
		}
	}

	cfg.raw = o

	// TODO: look for an 'type to object' function - for types that don't implement NewInstance
	// 'raw' config, not a problem.
	return nil // NewSlogError("MissingNew", "name", cfg.Name)
}

// GetResource returns a resource by name - all files are wrapped in
// Resource to add metadata.
func (a *ResourceStore) GetResource(n string) (*Resource, error) {
	cfg := a.loaded[n]
	if cfg != nil && cfg.raw != nil {
		return cfg, nil
	}

	// WIP: KIND/PATH - use first component to determine the kind
	ba := a.GetRawJson(n)
	if ba != nil {
		rs := &Resource{BaseName: n, Spec: ba}
		return rs, nil
	}

	return nil, nil
}

// GetRawJson will do an on-demand resource loading for resources not specified in the config.
func (a *ResourceStore) GetRawJson(name string) []byte {
	data1 := a.LoadedFS[name]
	if data1 != nil {
		return data1
	}

	// If a BaseDir is set - this is the main store, support env variables.
	if a.BaseDir != "" {
		envs := os.Getenv(name)
		if envs != "" {
			return []byte(envs)
		}
		data, err := findLocalJson(a.BaseDir + "/" + name)
		if data != nil {
			return data
		}
		if err != nil {
			return nil
		}
	}

	// check the filesystem.
	if a.FS != nil {
		dataF, err := a.FS.Open(name)
		if err == nil {
			data, err := io.ReadAll(dataF)
			if err == nil {
				return data
			}
		}
	}

	return nil
}

// Plugin loads a plugin compiled with
//
//	`go build -buildmode=plugin -o myplugin.so plugin.go`
//
// It should have a New method.
func (a *ResourceStore) Plugin(name string) (any, error) {
	p, err := plugin.Open(name)
	if err != nil {
		return nil, err
	}

	sym, err := p.Lookup("New")
	if err != nil {
		return nil, err
	}
	// sym should be a func - but I don't know the return value
	v := reflect.ValueOf(sym)
	if v.Type().NumIn() == 0 && v.Type().NumOut() == 1 {
		return v.Call(nil), nil
	}
	return nil, err
}

// If any of the configured objects implements 'Start', call it.
//
// Start implementing Caddy signature.
func (a *ResourceStore) Start() error {
	// Before starting, set dialer,  listener and other deps
	if a.Logger == nil {
		a.Logger = slog.Default()
	}
	// TODO: add a Dependencies() []string function to fine tune which objects the module wants.

	// Call Start, if it exists.
	for k, mm := range a.loaded {
		if sc, ok := mm.raw.(StarterContext); ok {
			err := sc.Start(a.appCtx)
			if err != nil {
				return err
			}
			a.Logger.Info("start_ctx", "name", k)
		}
		if sc, ok := mm.raw.(Starter); ok {
			err := sc.Start()
			if err != nil {
				return err
			}
			a.Logger.Info("start", "name", k)
		}
	}
	return nil
}

func (a *ResourceStore) Close() error {
	for _, v := range a.loaded {
		if c, ok := v.raw.(Closer); ok {
			c.Close()
		}
	}
	return nil
}

var startupTime = time.Now()

//func unmarshallLocalFile(base string, out interface{}) error {
//	data, err := findLocalJson(base)
//	if err != nil {
//		return err
//	}
//	if data != nil {
//		return unmarshal(data, out)
//	}
//
//	return nil
//}

// Configurations for the mesh. Besides 'mesh identity' and authn/authz, dynamic config is a main feature of the
// mesh.
//
// - JSON files in a base directory - this is included in this package.
// - HTTP with mesh auth - TODO
// - Yaml files - require adding a yaml parser ( and dependency )
// - K8S or other plugins
// - XDS - plugin.

//func (a *ResourceStore) Unmarshler(ext string) encoding.BinaryUnmarshaler {
//	return nil
//}

// findLocalJson will load a json file. Optionally will look for
// yaml, if yaml2json converter is configured, and will
// auto-convert it to json.
//
// 'base' does not include the extension, is relative to the working
// dir or absolute (caller will check).
func findLocalJson(base string) ([]byte, error) {

	if Yaml2Json != nil {
		fb, err := os.ReadFile(base + ".yaml")
		if err == nil {
			return Yaml2Json(fb)
		}
	}
	fb, err := os.ReadFile(base + ".json")
	if err == nil {
		return fb, err
	}

	return nil, nil
}

// TODO:
// - Init instead of Provision, pass Name and fs.FS
// - Kind
// - URL instead of name, with Kind first
// - ResourceKind, ResourceT
// - 'ant' style, but with json/yaml
// - Resource created in http.Do,
// - iterators
// - slog - for logs routing, metrics (vars registered as resources, in fs), traces.

/*
- Define interface for IP to identity registry
- use 254.0.0.0/8 and list of nets as 'local networks'
- .local with original meaning - all IPs are on the same CNI ('network')
- net.Conn -> identity (including HA Proxy / ztunnel and IP)

- use go template elements in values

*/
