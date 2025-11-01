package appinit

import (
	"expvar"
	"iter"
	"reflect"
	"strings"
)

// TypeRegistry is a schema of go types (structs) available for unmarshalling
// and use as interfaces in a dynamic config or invocation.
//
// Unlike Java, Class.forName() is not available.
// Instead, Go frameworks use their own registries and types self-register
// to the framework. Examples: protobufs, K8S, Caddy.
//
// Currently this is per app - represents code that is compiled in the
// binary. No ClassLoader equivalent - too complex.
//
// For dependency-free, use extvar to register a "class" object.
// This also allows inspecting the registered object types.
// The 'class' object can also be a singleton, used directly.

var appCodec = NewCodec()

// Codecs is a map of encoding types (json, etc) to interfaces for
// converting to/from []byte, fs.File or transport and objects that
// operate on the corresponding resource (can access and possibly
// modify the content).
//
// A Resource associates metadata with the content. A file system may use
//
//	the URL or file path to encode metadata, along with native metadata
//
// (xattr, .dir files, etc).
//
// Knowing the 'kind' and format using elements inside the object is not
// ideal (K8S makes it work, but with a high cost). The resource URL and
// file name, as well as 'content-type' are better places to encode this,
// as well as 'out of band'.
//
// HTTP Accept-Encoding is one way, but also complex and doesn't work
// for files.
//
// Using file extensions has the 'readability' advantage of being
// easy to understand but it is forcing a naming style.
//
// As a middle ground, when using HTTP the headers will take priority,
// and in configs and APIs the type can be explicitly configured.
//
// This package also deals with registering the 'New' or type object.
type Codecs struct {
	newObj map[string]newer
}

func (appCodec Codecs) Range() iter.Seq2[string, interface{}] {
	return func(fn func(name string, newer interface{}) bool) {
		for name, obj := range appCodec.newObj {
			if !fn(name, obj) {
				return
			}
		}
	}
}

func AppCodec() *Codecs {
	return appCodec
}

// Given a type or name, return a new instance.
// This is using the 'New' functions registered in the app or global.
//
// Used by 'Get' to create new instances for unmarshallin.
func (rs *Codecs) New(name string) any {
	np := strings.SplitN(name, "/", 2)
	name = np[0]
	newObj_, _ := appCodec.newObj[name]
	if n, ok := newObj_.(newer); ok {
		return n.New()
	}

	v := expvar.Get(name)
	if n, ok := v.(newer); ok {
		return n.New()
	}

	return nil
}

func NewCodec() *Codecs {
	return &Codecs{newObj: make(map[string]newer)}
}

// RegisterN registers a 'New' function with no parameters.
func RegisterN[T any](name string, newObj_ func() *T) {
	appCodec.newObj[name] = &resourceClassN[T]{new: newObj_}
}

// RegisterT registers a 'template' object that will be copied.
func RegisterT[T any](name string, t *T) {
	appCodec.newObj[name] = &resourceClassT[T]{T: t}
}

// Has a New method - 'any' type seems to match New() *T, so this works for
// functions that return an actual type.
type newer interface {
	New() any
}

// Equivalent with a Class in java.
type resourceClassN[T any] struct {
	new func() *T
}

func (rc *resourceClassN[T]) New() any {
	x := rc.new()
	return x
}

type resourceClassT[T any] struct {
	T *T
}

func (rc *resourceClassT[T]) New() any {
	// K8S: (*T) DeepCopy() *T
	var a any
	a = rc.T
	if dc, ok := a.(interface{ DeepCopy() any }); ok {
		return dc.DeepCopy()
	}

	var clone T
	clone = *rc.T

	// clone := reflect.New(reflect.ValueOf(*rc.T).Type()).Elem().Interface()
	return &clone
}

func RegisterAny(name string, newObj_ any) {
	appCodec.newObj[name] = &resourceClassReflect{newObj_}
}

type resourceClassReflect struct {
	builder any
}

func (rc *resourceClassReflect) New() any {
	m := reflect.ValueOf(rc.builder)
	// Registered a New() T function in the struct (with any name)
	if m.Type().Kind() == reflect.Func {
		// New function - no params, return the object.
		if m.Type().NumIn() == 0 &&
			m.Type().NumOut() == 1 {
			res := m.Call(nil)
			return res[0].Interface()
		}
	}
	return nil
}

// type TypeRegistry struct {
// 	Classes []Class

// 	Packages map[string]string

// 	//Deps map[string][]string
// }

// type Class struct {
// 	Package string

// 	// Name of the struct
// 	Name string

// 	// Builder is the name of the functions that builds the struct
// 	// Multiple functions with different params can be used.
// 	// Could also be a function on another type.
// 	Builders []string

// 	// List of interfaces or types that are required
// 	//Depends []string

// 	// List of interfaces that are implemented and can be used by other packages
// 	//Provides []string
// }
