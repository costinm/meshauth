package appinit

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"time"
)

/*

 Alternative K8S style: file name doesn't matter, content
 includes kind/apiVersion.
 This is less efficient - need to parse content as json to
 find the type. Using filename pattern avoids that - and
 is more consistent with http content-type pattern.
 Json-rpc is closer to k8s, but slightly different pattern:
 method is equivalent to content-type, params are a separate
 struct. K8S with 'spec' fits this model.

 I prefer using envelope (file, extension or dir name pattern, content-type)
 but json-rpc and k8s need to be supported too.
*/

// ResourceStore handles creating and configuring resources (or 'objects').
//
// A 'default' resource store is used for registering New() functions.
// A store can override the builder.
//
// Resources can be 'data only' (like K8S or proto) or active (like Caddy).
// Config or runtime data is loaded into the object, and methods may be called.
type ResourceStore struct {
	// Data contains K8S style resources, with a 'kind' encoding the type and a 'spec' encoding the data.
	Data []*Resource `json:"data,omitempty"`

	// LoadedFS contains an in-memory resource filesystem. Key encodes  the type, objects are lazy-loaded.
	// If not found here, the FS will be used.
	LoadedFS map[string]json.RawMessage `json:"fs,omitempty"`

	// Env contains a map of env variables, used instead of os.Getenv
	Env map[string]string `json:"env,omitempty"`

	// BaseDir is a path used as base directory for resources.
	BaseDir string `json:"base,omitempty"`

	Services []string `json:"services"`

	FS fs.FS `json:"-"`

	// Additional config sources - may be K8S cluster names, URLs, etc
	//Sources []string `json:"src,omitempty"`

	// All resources that are defined in the config or added explicitly
	loaded map[string]*Resource

	//Codecs

	appCtx context.Context

	Logger *slog.Logger
}

// Resource holds a chunk of bytes and metadata, and can be used to create a
// struct (object).
//
// It implements the fs.FileInfo interface and a partial fs.File, with
// Read() and Seek() not moving the pos.
//
// The name and metadata are used to identify a struct (object) where data
// can be unmarshalled and used.
//
// This is modeled as a file, but also based on K8S resource model, which encodes the
// type and metadata in the same object.
type Resource struct {
	// BaseName of the object - may use FQDN syntax, but no "/".
	//
	// Naming conventions:
	// - NAME.KIND.ENCODING
	//   - ENCODING can be json, yaml or any registered serializer
	//   - kind is any registered type. K8S apiVersion is mangled replacing . and / with _
	// - the parent dir is the namespace.
	// - suffix is the type - matched in the ResourceKind map. Can be a
	//  long qualfied name like in K8S, but for now aliases are registered.
	// - base name is the name of the object.
	// - resources are loaded on-demand. Once closed, the object can be removed
	// from memory.
	// - some kinds of resources are dirs.
	//
	BaseName string `json:"name,omitempty"`

	// This matches K8S style, it represents extended attributes.
	ObjectMeta `json:"meta,omitempty"`

	// Kind is the type of the object, K8S-based - is an extended attribute
	Kind string `json:"kind,omitempty"`

	// Only used with K8S - appended to Kind, with version omitted for mapping
	// to Codec. Used in REST requests to indicate a K8S-style server.
	APIVersion string `json:"apiVersion,omitempty"`

	Path  string
	Query string

	// References map field names in the object to other config objects.
	// After the 'M' field is populated (before Start), the Ref will be used
	// to set the field to the value of the named object.
	//
	// Start should be able to fill in defaults if needed.
	//
	Ref map[string]string `json:"ref,omitempty"`

	// Context is set for resources that are loaded on demand or ephemeral.
	// Can be a http or gRPC context.
	Context context.Context

	// Spec is the raw bytes, raw is the object. Each can be generated from the
	// other, using the metadata for conversion.

	// RawMessage is a []byte, for delayed processing in json.
	// The bytes can be shared or passed without decoding the raw object.
	// Multiple objects can be decoded from same bytes, and can be passed to WASM or other processes.
	Spec json.RawMessage `json:"spec,omitempty"`

	// The instance of the object. Lazy loaded using a codec.
	// Returned by Sys().
	raw any `json:"-"`
}

// ObjectMeta includes metadata about a resource.
//
// This is in addition to Kind, ApiVersion - which in K8S are top level, but
// also part of the path.
//
// In K8S this is part of each object - but it doesn't have to be
// from generic API perspective.
//
// From 'filesystem abstraction' perspective, this is 'extended attributes',
// and can be represented as a separate database.
//
// Things like embeddings, sha, etc are also metadata.
//
// Different storage systems may hold 'metadata' about a resource.
//
// "Desktop" spec defines Type (Application (.desktop), Link to URL,
// Directory with .directory extension ) and Name.
// Application has Path and Exec.
//
// Apple uses ._FILEs (AppleDouble) for metadata. AppleSingle combines
// meta and file, with a binary header listing the sections. Entry IDs
// are used.
//
// Tracker (gnome) now uses sqlite.
type ObjectMeta struct {
	// Base name, unique in namespace
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`

	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

// Open and ReadFile are used for resources that are filesystems.
//func (cfg *Resource) Open(name string) (fs.File, error) {
//	return &ResourceFile{Resource: cfg}, nil
//}
//
//func (cfg *Resource) ReadFile(name string) ([]byte, error) {
//	return cfg.Spec, nil
//}

func (cfg *Resource) Info() (fs.FileInfo, error) {
	return cfg, nil
}

// Base name of the file
func (cfg *Resource) Name() string {
	return cfg.BaseName
}

func (cfg *Resource) Size() int64 {
	return int64(len(cfg.Spec))
}

// Dir interface
func (cfg *Resource) Type() fs.FileMode {
	// ModeDir
	// Device, Socket, CharDevice, etc.
	return 0755
}

func (cfg *Resource) Mode() fs.FileMode {
	// uint32
	// TODO: encode 'read only' and 'executable'
	return 0755
}

func (cfg *Resource) ModTime() time.Time {
	return time.Now()
}

func (cfg *Resource) IsDir() bool {
	return false
}

func (cfg *Resource) Sys() any {
	if cfg.raw != nil {
		return cfg.raw
	}

	if o := appCodec.New(cfg.BaseName); o != nil {
		if len(cfg.Spec) > 0 {
			err := unmarshal(cfg.Spec, o)
			if err != nil {
				return nil
			}
		}
		cfg.raw = o
	}
	return cfg.raw
}

// Stat, Read and Close are the FS interface.
func (cfg *Resource) Read(bytes []byte) (int, error) {
	return 0, io.EOF
}

func (cfg *Resource) Stat() (fs.FileInfo, error) {
	return cfg, nil
}

func (cfg *Resource) Close() error {
	// resource are loaded in memory, we may free the cache for on-demand ones
	return nil
}

// ReadAt is an optimized interface, avoids allocating
func (cfg *Resource) ReadAt(bytes []byte, off int64) (int, error) {
	return copy(bytes, cfg.Spec[off:]), nil
}

var (
	_ fs.FileInfo    = (*Resource)(nil)
	_ fs.File        = (*ResourceFile)(nil)
	_ fs.ReadDirFile = (*ResourceDir)(nil)
)

// ResourceFile implements the io.File - mainly the cursor for Read().
type ResourceFile struct {
	// The Spec field must be set
	*Resource

	// For the read interface.
	pos int
	err error
}

func (cfg *ResourceFile) Read(bytes []byte) (int, error) {
	if cfg.err != nil {
		return 0, cfg.err
	}
	if len(cfg.Spec) <= cfg.pos {
		return 0, io.EOF
	}
	cnt := copy(bytes, cfg.Spec[cfg.pos:])
	cfg.pos += cnt
	return cnt, nil
}

func (cfg *ResourceFile) Seek(off int64, x int) (int64, error) {
	switch x {
	case io.SeekStart:
		cfg.pos = int(off)
	case io.SeekCurrent:
		cfg.pos += int(off)
	case io.SeekEnd:
		cfg.pos = len(cfg.Spec) + int(off)
	}
	if cfg.pos < 0 {
		cfg.pos = 0
	}
	if cfg.pos > len(cfg.Spec) {
		cfg.pos = len(cfg.Spec)
	}

	return int64(cfg.pos), nil
}

type ResourceDir struct {
	BaseName string
}

func (cfg *ResourceDir) Name() string {
	return cfg.BaseName
}

func (cfg *ResourceDir) Size() int64 {
	return 0
}

func (cfg *ResourceDir) Mode() fs.FileMode {
	return 0
}

func (cfg *ResourceDir) ModTime() time.Time {
	return time.Time{}
}

func (cfg *ResourceDir) IsDir() bool {
	return true
}

func (cfg *ResourceDir) Sys() any {
	return nil
}

func (cfg *ResourceDir) Read(bytes []byte) (int, error) {
	return 0, io.EOF
}

func (cfg *ResourceDir) Stat() (fs.FileInfo, error) {
	return cfg, nil
}

func (cfg *ResourceDir) Close() error {
	// resource are loaded in memory, we may free the cache for on-demand ones
	return nil
}

func (cfg *ResourceDir) ReadDir(n int) ([]fs.DirEntry, error) {
	return []fs.DirEntry{&Resource{}}, nil
}
