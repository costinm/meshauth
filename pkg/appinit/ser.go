package appinit

import (
	"context"
	"encoding/json"
)

/*
Serialization (marshal/unmarshal)

The main problem in Golang - compared with Java - is the lack of
Class.forName. That's because Go compiler will not link any code that
is not referenced, reducing binary size, so it can't hold a huge list
of classes that are never used.

K8S, Proto and all others handle this by keeping a registry of 'kinds'
and constructors.

The second problem is finding what codec/unmarhsaler to use for a blob
of bytes. K8S uses a 'Kind' field at the top level, but also encodes
the kind in the URLs (except Event).

A cleaner approach may be what Mail, Http and Markdown does - have a
header with all metadata, clearly separated from body.
Using the filename is also possible - but labels and other metadata
will need to go to a separate file ( the 'dir' ) or xattr/setfatter
or separate global database/file.

A Resource encapsulates file (reference or in-memory cache), metadata and
a pointer to a real object. Not all need to be set.

A File represents raw data - the directory has some metadata. Open/Close
allow tracking if the file is in use.

A codec can map from File or []byte to Resource by handling serialization.



*/

// An object is create with New(), data is unmarshalled into it, an
// Init function called - then it can be used.
// The Resource type wraps the bytes, object and metadata.

// Just read - not full codec.
var Unmarshallers = map[string]func([]byte, any) error{}

var Yaml2Json func([]byte) ([]byte, error)

func unmarshal(data []byte, out any) error {
	f := Unmarshallers["json"]
	if f != nil {
		return f(data, out)
	}
	return json.Unmarshal(data, out)
}

// ProcessJSON will take a json and use the registered types
// to unmarshall each key.
func (appCodec *Codecs) ProcessJSON(ctx context.Context, s string) (map[string]any, error) {
	// TODO: use custom unmarshaller (yaml, etc)
	cfg := map[string]json.RawMessage{}

	err := unmarshal([]byte(s), &cfg)
	if err != nil {
		return nil, err
	}

	res := map[string]any{}

	for name, data := range cfg {
		r := appCodec.New(name)
		if r != nil {
			r, err = appCodec.InitObject(ctx, r, data)
			if err != nil {
				res[name] = err
				continue
			}

			res[name] = r
		}
	}

	return res, nil
}

// TODO: use Resource or File ( so it has encoding, Name )

// InitObject will return an object instance with the data unmarshalled into it.
// 'r' is the registered object - which may be an instance or a constructor.
// It does not provision the object - just unmarshal
func (appCodec *Codecs) InitObject(ctx context.Context, r any, data []byte) (any, error) {

	if onew, ok := r.(ObjInitializer); ok {
		real, err := onew.NewInstance(ctx)
		if err != nil {
			return r, err
		}
		r = real
	}

	if len(data) > 0 {
		err := unmarshal(data, r)
		if err != nil {
			return r, err
		}
	}

	return r, nil
}

type WithResourceStorer interface {
	WithResourceStore(any)
}

// ProcessJSONSpec handles a K8S-like object with a 'spec' field containing
// data, Kind, and APIVersion fields describing the kind.
func (appCodec *Codecs) ProcessJSONSpec(ctx context.Context, s []byte) (any, error) {

	// TODO: use custom unmarshaller (yaml, etc)
	cfg := Resource{}

	err := unmarshal(s, &cfg)
	if err != nil {
		return nil, err
	}

	// TODO: kind, apiVersion
	r := appCodec.New(cfg.BaseName)
	if r == nil {
		return nil, nil
	}
	if len(cfg.Spec) > 0 {
		r, err = appCodec.InitObject(ctx, r, cfg.Spec)
		if err != nil {
			return nil, err
		}
	} else {
		r, err = appCodec.InitObject(ctx, r, s)
		if err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}
