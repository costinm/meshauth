package meshauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// RESTRequest is a REST or K8Service style request. Will be used with a Dest.
//
// It is based on/inspired from kelseyhightower/konfig - which uses the 'raw'
// K8Service protocol to avoid a big dependency. Google, K8Service and many
// other APIs have  a raw representation and don't require complex
// client libraries and dependencies.
//
// No code generation or protos are used - raw JSON in []byte is used, caller
// can handle marshalling.
//
// Close to K8Service raw REST client - but without the builder style.
type RESTRequest struct {

	// Must be set for namespaced resources ('default' can be used)
	// If not set - cluster-wide resources.
	Namespace string

	// Type - required for normal K8Service resources.
	Kind string

	// Namespaced name - required for normal K8Service resources.
	Name string

	// If set - will be used instead of /api/v1/namespaces/{NS}/{KIND}s/{NAME}
	Path string

	// This is the resource body, typically json. Will be uploaded as POST.
	Spec []byte

	// If set, will be added at the end (must include ?). For example ?watch=0
	Query string

	// Defaults to GET if no Spec, POST otherwise.
	Method string

	Dest *Dest
}

func (d *Dest) RestClient(g, v string) (*RESTRequest, error) {
	return &RESTRequest{
		Dest: d,
	}, nil
}

func (k *RESTRequest) Post() *RESTRequest {
	k.Method = "POST"
	return k
}

func (k *RESTRequest) Do(ctx context.Context, dest *Dest) ([]byte, error) {
	r := k.HttpRequest(ctx, dest)
	res, err := dest.HttpClient().Do(r)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New(fmt.Sprintf("K8Service error %d %s", res.StatusCode, string(data)))
	}
	return data, nil
}

// HttpRequest creates the populated http.Request for connecting to
// a K8S-like server.
//
// The destination has the Addr and config (credentials, etc).
func (kr *RESTRequest) HttpRequest(ctx context.Context, d *Dest) *http.Request {
	var path string
	if kr.Path == "" {
		if kr.Namespace != "" {
			path = fmt.Sprintf("/api/v1/namespaces/%s/%ss", kr.Namespace, kr.Kind)
		} else {
			path = "/apis/" + kr.Kind
		}
		if kr.Name != "" { // else - list request
			path = path + "/" + kr.Name
		}
	} else {
		path = kr.Path
	}

	if kr.Query != "" {
		path = path + kr.Query
	}

	var req *http.Request
	m := kr.Method
	if kr.Method == "" {
		if kr.Spec == nil {
			m = "GET"
		} else {
			m = "POST"
		}
	}
	if kr.Spec == nil {
		req, _ = http.NewRequestWithContext(ctx, m, d.Addr+path, nil)
	} else {
		req, _ = http.NewRequestWithContext(ctx, m, d.Addr+path, bytes.NewReader(kr.Spec))
		req.Header.Add("content-type", "application/json")
	}

	if d.TokenProvider != nil {
		t, err := d.TokenProvider.GetToken(ctx, d.Addr)
		if err == nil {
			req.Header.Add("authorization", "Bearer "+t)
		}
	}
	return req

}

// Load will populate the object from a K8Service-like service.
//
// 'kind' can be 'configmap', 'secret', etc for using K8Service-style URL format
func Load(ctx context.Context, d *Dest, obj interface{}, kind, ns string, name string) error {

	rr := &RESTRequest{
		Namespace: ns,
		Kind:      kind,
		Name:      name,
	}

	res, err := d.HttpClient().Do(rr.HttpRequest(ctx, d))
	if err != nil {
		return err
	}

	data, err := io.ReadAll(res.Body)
	err = json.Unmarshal(data, obj)
	if err != nil {
		return err
	}

	return nil
}
