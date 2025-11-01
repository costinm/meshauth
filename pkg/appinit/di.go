package appinit

import (
	"context"
	"log"
	"reflect"
)

// DI (dependency injection) is a pretty inflexible and ugly design, but
// it can be useful in reducing some boilerplate and dependencies, and to
// interact with libraries that are not designed with composition and resources
// in mind.
//
// It is using reflection and a config to 'patch' objects - with a bit of
// automatic configuration/wiring.

// type DI struct {
// 	// Key is a resource kind. Value is a map of fields to resources
// 	Links map[string]DIResCfg
// }

// type DIResCfg struct {
// 	FieldsToResources map[string]string
// }

func (a *ResourceStore) resolveRef(ctx context.Context, cfg *Resource, o any) error {
	for k, v := range cfg.Ref {
		dv, err := a.Get(ctx, v)
		if err != nil {
			return err
		}

		if dv != nil {
			m := reflect.ValueOf(cfg.Sys())
			f := m.Elem().FieldByName(k)
			dvv := reflect.ValueOf(dv)
			if dvv.Type().Implements(f.Type()) {
				f.Set(dvv)
			} else {
				if dvv.Kind() == reflect.Ptr {
					dvv = dvv.Elem()
				}
				if dvv.Type().Implements(f.Type()) {
					f.Set(dvv)
				} else {
					log.Println("Not implementing ", dvv.Type(), f.Type())
				}
			}
		}
	}
	return nil
}

// RegisterAny register a constructor for a module (tool) or a struct
// implementing DeepCopy (falling back to reflect.New()
//
// Should return a reference to an object that has can unmarshall
// json configs, and implements various methods.
//
// In particular:
// - Start method indicates a long-running component.
// - Run performs a sync operation on the module data.
// - Stop or Close is called when the module is removed from the system.
//
// The newObj function is called with the context of the app when it is needed, either
// by config or runtime operations. It may load on-demand plugins or wasm or other components.
// It is not called for other reasons.
