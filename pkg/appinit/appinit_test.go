package appinit

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestResourceStore(t *testing.T) {
	//SetupJson()

	//RegisterMods()

	b := os.DirFS("../testdata/ca")
	ctx := context.Background()
	cs := AppResourceStore()

	err := cs.Load(ctx, b, "../testdata/ca")
	if err != nil {
		panic(err)
	}

	err = cs.Start()
	if err != nil {
		panic(err)
	}

	// yaml can't really unmarshall json structs if they have RawJson
	csb, err := json.Marshal(cs)

	raw := map[string]any{}
	err = json.Unmarshal(csb, &raw)
	if err != nil {
		panic(err)
	}
	//csb, err = yaml.Marshal(raw)
	//if err != nil {
	//	panic(err)
	//}
	//t.Log(string(csb))

}

type TestModule struct {
	appCtx context.Context

	Path string

	Cfg map[string]any `json:",inline""`

	// Doesn't really work with std json package
	Extra interface{} `json:",inline"`
}

func NewTestModule() *TestModule {
	return &TestModule{Path: "/NewTestModule", Cfg: map[string]any{}}
}

type TestDC struct {
	appCtx context.Context

	Path string

	Cfg map[string]any `json:",inline"`

	// Doesn't really work with std json package
	Extra interface{} `json:",inline"`
}

func (t *TestDC) DeepCopy() any {
	return &TestDC{Path: "deep copy", Cfg: t.Cfg, Extra: t.Extra}
}

func TestNew(t *testing.T) {
	RegisterN[TestModule]("test-new1", NewTestModule)
	RegisterT[TestModule]("test-t", &TestModule{Path: "shallow", Cfg: map[string]any{"a": "b"}})
	RegisterT("testdc", &TestDC{Path: "deepcopy_template"})

	rcdc := appCodec.New("testdc")
	t.Log(rcdc)

	rc2 := appCodec.newObj["test-new1"]
	if n, ok := rc2.(newer); ok {
		val3 := n.New()
		t.Log("newer", val3, reflect.TypeOf(val3))
		val3.(*TestModule).Cfg["a"] = "c"
		val3.(*TestModule).Path = "c"
	} else {
		t.Error("Not newer ", rc2, reflect.TypeOf(rc2))
	}

	if n, ok := rc2.(newer); ok {
		val4 := n.New()
		t.Log("NewerN", val4, reflect.TypeOf(val4))
	} else {
		t.Error("Not Newer1", rc2, reflect.TypeOf(rc2))
	}

	rc2 = appCodec.newObj["test-t"]
	if n, ok := rc2.(newer); ok {
		val3 := n.New()
		t.Log("NewerT[any]", val3, reflect.TypeOf(val3))
		val3.(*TestModule).Cfg["a"] = "c"
		val3.(*TestModule).Path = "c"
	} else {
		t.Error("Not newer ", rc2, reflect.TypeOf(rc2))
	}

	if n, ok := rc2.(newer); ok {
		val4 := n.New()
		t.Log("NewerT", val4, reflect.TypeOf(val4))
	} else {
		t.Error("Not Newer1", rc2, reflect.TypeOf(rc2))
	}

}
func TestInit2(t *testing.T) {

	ctx := context.Background()

	RegisterN("test", func() *TestModule {
		return &TestModule{}
	})

	obj, err := AppCodec().ProcessJSON(ctx, `
		{
			"test": {
				"path": "../../testdata/ca",
			  "cfg": {"foo": "bar"},
			  "extraname": "foo"
			}
		}
`)

	if err != nil {
		t.Fatal(err)
	}

	tt := obj["test"]
	t.Log(tt)

}

func TestInit(t *testing.T) {
	ctx := context.Background()

	RegisterN("test", func() *TestModule {
		return &TestModule{}
	})

	RegisterT("test2", &TestModule{Path: "/test1"})

	//rs := meshauth.NewResourceStore()
	//rs.Load(ctx, "")
	obj, err := AppCodec().ProcessJSON(ctx, `
		{
			"test": {
				"path": "../../testdata/ca",
			  "cfg": {"foo": "bar"},
			  "extraname": "foo"
			}
		}
`)

	if err != nil {
		t.Fatal(err)
	}

	tt := obj["test"]
	t.Log(tt)

}

// This appears to work - but doesn't help that much, for code to be linked in
// it needs to be referenced somehow.
//
// If we link the object by referencing - we can as well register it.
func TestRefl(t *testing.T) {
	// Open the current executable (Linux-specific)
	f, err := elf.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Get the symbol table
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}

	// Iterate through symbols (simplified - needs more robust filtering)
	for _, sym := range syms {
		if elf.ST_BIND(sym.Info) == elf.STB_GLOBAL { // Filter global symbols (exported)
			if strings.Contains(sym.Name, ".NewNative_") {
				fmt.Println(sym.Name) // Print the symbol name
				// ... further processing ...
				myFunc := NewNative_
				sv := sym.Value
				funcPtr := reflect.ValueOf(&sv).Pointer()
				funcValue := reflect.New(reflect.TypeOf(myFunc)).Elem()
				*(*uintptr)(unsafe.Pointer(funcValue.UnsafeAddr())) = funcPtr

				args := []reflect.Value{}
				results := funcValue.Call(args)

				fmt.Println(results)

				NewNative_()
			}
		}
	}
}

func New_() any {
	log.Println("Called sym")
	return "sym"
}

func NewNative_() any {
	log.Println("Called")
	return "native"
}

type NewF func() any

func TestError(t *testing.T) {
	err1 := errors.New("example")

	//ctx := context.Background()
	e := NewSlogError("test", "example", 1)

	w2 := fmt.Errorf("Formatted %w %w", err1, e)

	e3 := errors.Join(e, err1, w2)

	bb1 := &bytes.Buffer{}
	lt1 := slog.NewTextHandler(bb1, &slog.HandlerOptions{AddSource: true})
	//	var a any
	//	a = e3

	//if ee, ok := a.(RecordError); ok {
	//	ee.LogHandle(lt1)
	//}

	var re RecordError
	if !errors.Is(e3, e) {
		t.Error("Not a RecordError")
	}

	var re1 any
	re1 = &re
	// This is the recommended way to cast an error to a RecordError (unwrapps)
	if errors.As(e3, re1) {
		re.LogHandle(lt1)
	}


	bb, err := json.MarshalIndent(ErrorToMap(e), " ", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(bb))
}
