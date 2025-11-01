package mhttp

import (
	"context"
	"net/http"
)

type Resolver interface {
	Resolve(ctx context.Context, name string) (any, error)
}

type GatewaySpec struct {
	Mux *http.ServeMux `json:"-"`

	Resolver Resolver `json:"-"`
}

// HttpRouteSpec is a standalone route
type HttpRouteSpec struct {

	ParentRefs []ParentReference `json:"parentRefs,omitempty"`

	Hostnames []string `json:"hostnames,omitempty"`

	Rules []HttpRouteRule `json:"rules,omitempty"`

	Resolver Resolver `json:"-"`
}

type ParentReference struct {
	// Group is the group of the referent.
	// When unspecified, "gateway.networking.k8s.io" is inferred.
	// To set the core API group (such as for a "Service" kind referent),
	// Group must be explicitly set to "" (empty string).
	//
	// Support: Core
	//
	// +kubebuilder:default=gateway.networking.k8s.io
	// +optional
	Group string `json:"group,omitempty"`

	// Kind is kind of the referent.
	//
	// There are two kinds of parent resources with "Core" support:
	//
	// * Gateway (Gateway conformance profile)
	// * Service (Mesh conformance profile, ClusterIP Services only)
	//
	// Support for other resources is Implementation-Specific.
	//
	// +kubebuilder:default=Gateway
	// +optional
	Kind string `json:"kind,omitempty"`

	Namespace string `json:"namespace,omitempty"`

	// Name is the name of the referent.
	//
	// Support: Core
	Name string `json:"name"`

	// SectionName is the name of a section within the target resource. In the
	// following resources, SectionName is interpreted as the following:
	//
	// * Gateway: Listener name. When both Port (experimental) and SectionName
	// are specified, the name and port of the selected listener must match
	// both specified values.
	// * Service: Port name. When both Port (experimental) and SectionName
	// are specified, the name and port of the selected listener must match
	// both specified values.
	//
	// Implementations MAY choose to support attaching Routes to other resources.
	// If that is the case, they MUST clearly document how SectionName is
	// interpreted.
	//
	// When unspecified (empty string), this will reference the entire resource.
	// For the purpose of status, an attachment is considered successful if at
	// least one section in the parent resource accepts it. For example, Gateway
	// listeners can restrict which Routes can attach to them by Route kind,
	// namespace, or hostname. If 1 of 2 Gateway listeners accept attachment from
	// the referencing Route, the Route MUST be considered successfully
	// attached. If no Gateway listeners accept attachment from this Route, the
	// Route MUST be considered detached from the Gateway.
	//
	// Support: Core
	//
	// +optional
	SectionName string `json:"sectionName,omitempty"`

	// Port is the network port this Route targets. It can be interpreted
	// differently based on the type of parent resource.
	//
	// When the parent resource is a Gateway, this targets all listeners
	// listening on the specified port that also support this kind of Route(and
	// select this Route). It's not recommended to set `Port` unless the
	// networking behaviors specified in a Route must apply to a specific port
	// as opposed to a listener(s) whose port(s) may be changed. When both Port
	// and SectionName are specified, the name and port of the selected listener
	// must match both specified values.
	//
	// <gateway:experimental:description>
	// When the parent resource is a Service, this targets a specific port in the
	// Service spec. When both Port (experimental) and SectionName are specified,
	// the name and port of the selected port must match both specified values.
	// </gateway:experimental:description>
	//
	// Implementations MAY choose to support other parent resources.
	// Implementations supporting other types of parent resources MUST clearly
	// document how/if Port is interpreted.
	//
	// For the purpose of status, an attachment is considered successful as
	// long as the parent resource accepts it partially. For example, Gateway
	// listeners can restrict which Routes can attach to them by Route kind,
	// namespace, or hostname. If 1 of 2 Gateway listeners accept attachment
	// from the referencing Route, the Route MUST be considered successfully
	// attached. If no Gateway listeners accept attachment from this Route,
	// the Route MUST be considered detached from the Gateway.
	//
	// Support: Extended
	//
	// +optional
	Port int32`json:"port,omitempty"`
}

type HttpRouteRule struct {
	Matches []HTTPRouteMatch `json:"matches,omitempty"`
	BackendRefs []BackendRef `json:"backendRefs,omitempty"`

}

type BackendRef struct {
	// Group is the group of the referent. For example, "gateway.networking.k8s.io".
	// When unspecified or empty string, core API group is inferred.
	//
	// +optional
	// +kubebuilder:default=""
	Group string `json:"group,omitempty"`

	// Kind is the Kubernetes resource kind of the referent. For example
	// "Service".
	//
	// Defaults to "Service" when not specified.
	//
	// ExternalName services can refer to CNAME DNS records that may live
	// outside of the cluster and as such are difficult to reason about in
	// terms of conformance. They also may not be safe to forward to (see
	// CVE-2021-25740 for more information). Implementations SHOULD NOT
	// support ExternalName Services.
	//
	// Support: Core (Services with a type other than ExternalName)
	//
	// Support: Implementation-specific (Services with type ExternalName)
	//
	// +optional
	// +kubebuilder:default=Service
	Kind string `json:"kind,omitempty"`

	// Name is the name of the referent.
	Name string `json:"name"`

	// Namespace is the namespace of the backend. When unspecified, the local
	// namespace is inferred.
	//
	// Note that when a namespace different than the local namespace is specified,
	// a ReferenceGrant object is required in the referent namespace to allow that
	// namespace's owner to accept the reference. See the ReferenceGrant
	// documentation for details.
	//
	// Support: Core
	//
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Port specifies the destination port number to use for this resource.
	// Port is required when the referent is a Kubernetes Service. In this
	// case, the port number is the service port number, not the target port.
	// For other resources, destination port might be derived from the referent
	// resource or this field.
	//
	// +optional
	Port int32 `json:"port,omitempty"`

	// Weight specifies the proportion of requests forwarded to the referenced
	// backend. This is computed as weight/(sum of all weights in this
	// BackendRefs list). For non-zero values, there may be some epsilon from
	// the exact proportion defined here depending on the precision an
	// implementation supports. Weight is not a percentage and the sum of
	// weights does not need to equal 100.
	//
	// If only one backend is specified and it has a weight greater than 0, 100%
	// of the traffic is forwarded to that backend. If weight is set to 0, no
	// traffic should be forwarded for this entry. If unspecified, weight
	// defaults to 1.
	//
	// Support for this field varies based on the context where used.
	//
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000000
	Weight *int32 `json:"weight,omitempty"`
}


type HTTPRouteMatch struct {
	// Path specifies a HTTP request path matcher. If this field is not
	// specified, a default prefix match on the "/" path is provided.
	//
	// +optional
	// +kubebuilder:default={type: "PathPrefix", value: "/"}
	Path *TypeValue `json:"path,omitempty"`

	// Headers specifies HTTP request header matchers. Multiple match values are
	// ANDed together, meaning, a request must match all the specified headers
	// to select the route.
	//
	// +listType=map
	// +listMapKey=name
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Headers []TypeNameValue `json:"headers,omitempty"`

	// QueryParams specifies HTTP query parameter matchers. Multiple match
	// values are ANDed together, meaning, a request must match all the
	// specified query parameters to select the route.
	//
	// Support: Extended
	//
	// +listType=map
	// +listMapKey=name
	// +optional
	// +kubebuilder:validation:MaxItems=16
	QueryParams []TypeNameValue `json:"queryParams,omitempty"`

	// Method specifies HTTP method matcher.
	// When specified, this route will be matched only if the request has the
	// specified method.
	//
	// Support: Extended
	//
	// +optional
	Method string `json:"method,omitempty"`
}

type TypeNameValue struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name"`
	Value string `json:"value"`
}

type TypeValue struct {
	Type string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}


func NewGateway() *GatewaySpec {
	return &GatewaySpec{
		Mux: http.NewServeMux(),
	}
}

func (g *GatewaySpec) Provision(ctx context.Context) error {

	return nil
}

func (r *HttpRouteSpec) Provision(ctx context.Context) error {

	return nil
}
