# IAM

Authentication and Authorization (authn/authz) are some of the most unnecessarily complex and confusing aspects 
of networking, with countless terms and APIs.

The simplistic view is that a request is first authenticated (mTLS, JWT, Oauth2 access tokens - plus many other forms),
and then the identity plus request URL/headers/metadata are passed to the 'authz' which allows or denies. Most 
of the focus is in picking one method to authenticate and one implementation to authorize (with everyone arguing
that their implementation is best - and most vendors supporting their unique implementation).

K8S, Istio and few others attempt to define some common APIs - but most of the times they are also really 
picking a specific implementation and attempt to call it a 'standard' API.

Reality is far more complicated - but mostly because we attempt to fit reality in this model.

The end goal is to apply policies on each request - 'allow/deny', but also more subtle things like 'set a cookie in
the response' or 'append some headers'. The input is a subset of the request info (URL, peer address, certificates,
headers) and sometimes even part of the request body. Because the policies need to be applied before the request 
is executed or forwarded, lowest possible latency is critical. For Gateways scale ( number of policies, identities,
hostnames) is also critical. Based on the type of request and workload, there is a range of options that can be 
combined.

It is important to understand that 'policy' doesn't mean only allow/deny - may also mean 'route' and 'modify 
request'. Both are important for security - the application will rely on some headers added by the policy to
serve the request. For example Istio ExtAuthz provide various options. 

## IAM and RBAC

Google (and other) IAMs are very similar to RBAC: the policy is based on an identity (who, principal), a resource and an 
operation (what). The 'role' is a mix of operation and resource type (role/logging.viewer).

To simplify management and understanding, a set of operations and resource type is grouped in a 'role', 
and the users are 'bound' to the role. The binding may be specific to a resource (storage bucket) or project 
wide for the resource type.

"Permission" is service.resource.verb (pubsub.subscriptions.consume) and the set of permissions is the role. 

Users can define custom roles and permissions.

So for a Google policy - defined as 'bindings' between roles and a list of principals, the equivalent is a list of 

(principal, verb, service.resource).

POST https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:testIamPermissions -d `{
"permissions":  [
"resourcemanager.projects.get",
"resourcemanager.projects.delete"
]
}`

In K8S RBAC, similar bindings are used - the (verb+resource) are grouped in Role and the
lists of principal associated in RoleBindings. 

Istio and Network Policy are a bit different - the rule combines principals (either as identity or
source identified by namespace and labels) with the resource (identified as workload selector).

In most cases some form of 'conditional' are supported - CEL or match rules.

## External authz

In Istio, this is configured as

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: ext-authz
  namespace: istio-system
spec:
  # For Gateway API or Waypoints - this corresponds to the generated names
  selector:
    matchLabels:
      app: istio-ingressgateway

  action: CUSTOM
    
  # Currently defined in MeshConfig.
  # TODO: use a Service or ServiceEntry with label
  provider:
    name: "my-ext-authz-service"
    
  # Rules apply first - the call is made only if the rules match
  rules:
  - to:
    - operation:
        paths: ["/admin/*"]
```

Mesh Config:

```yaml
extensionProviders:
# The name "my-ext-authz-service" is referred to by the authorization policy in its provider field.
- name: "my-ext-authz-service"
  # The "envoyExtAuthzGrpc" field specifies the type of the external authorization service is implemented by the Envoy
  # ext-authz filter gRPC API. The other supported type is the Envoy ext-authz filter HTTP API.
  # See more in https://www.envoyproxy.io/docs/envoy/v1.16.2/intro/arch_overview/security/ext_authz_filter.
  envoyExtAuthzGrpc:
    # The service and port specifies the address of the external auth service, "ext-authz.istio-system.svc.cluster.local"
    # means the service is deployed in the mesh. It can also be defined out of the mesh or even inside the pod as a separate
    # container.
    service: "ext-authz.istio-system.svc.cluster.local"
    port: 9000
```

Envoy side defines a http_filter with a cluster_name, type grpc (envoy_grpc) or http.
Settings are timeout, include_peer_certificate, 

The 'CheckRequest' may include "with_request_body" (max, partial, as bytes).

Http also supports failure_mode_allow.

CheckResponse may include dynamic_metadata which will be set on request, and in http 'dynamic_metadata_from_headers'.





