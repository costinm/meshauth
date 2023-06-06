# Istio environment

Survey of current Istio security/bootstrap settings. 
Based on https://istio.io/latest/docs/reference/commands/pilot-agent and injected pods, filtering only the Auth and bootstrap env.

The goal of meshauth is to simplify and reduce user config overhead, 
so attempting to identify what is actually required and in which platform.


On OSS:
- POD_NAME= metadata.name - usually same as `hostname`
- POD_NAMESPACE= metadata.namespace - can be extracted from K8S JWT or cert.
- INSTANCE_IP = status.podIP - from interfaces
- SERVICE_ACCOUNT = spec.serviceAccountName (default)		Name of service account - from cert or JWT
- HOST_IP = status.hostIP - not clear why it is needed
- PILOT_CERT_PROVIDER = istiod - use the config map mounted on .... (redundant, it's the default)
- CA_ADDR=istiod.istio-system.svc:15012 ( redundant )
- PROXY_CONFIG = {}
- ISTIO_META_CLUSTER_ID = Kubernetes - not very useful...
- ISTIO_META_WORKLOAD_NAME = based on deployment (fortio) - telemetry only, not security related.
- ISTIO_META_OWNER =  kubernetes://apis/apps/v1/namespaces/fortio-asm/deployments/fortio


- ISTIO_META_MESH_ID = cluster.local - redundant, should be based on trust domain, from cert.
- TRUST_DOMAIN=cluster.local - redundant, should be extracted from cert (doesn't need to be included in the CSR).
- "--domain" - defaults to $(POD_NAMESPACE).svc.cluster.local. Redundant, should be removed.


On ASM:

- "--stsPort" - if set STS (token) service enabled, ASM sets it to 15463. We should have this on by default in OSS as well, and use it as a local MDS and authn token proxy. Should 
 return GCP access tokens for the default ASM GSA if running in ASM, if accessing googleapis.com. Should return JWTs with the right audience otherwise - signed by Google if an account is specified, falling back to K8S TokenRequest.


- PILOT_CERT_PROVIDER = system - if pilot uses public certs. Redundant, based on address
- POD_NAME= metadata.name - usually same as `hostname`
- POD_NAMESPACE= metadata.namespace - can be extracted from K8S JWT or cert. 
- INSTANCE_IP = status.podIP
- SERVICE_ACCOUNT = spec.serviceAccountName (default)		Name of service account
- HOST_IP = status.hostIP
- PROXY_CONFIG = {"discoveryAddress":"meshconfig.googleapis.com:443","proxyMetadata":{"CA_PROVIDER":"GoogleCA","CA_ROOT_CA":"/etc/ssl/certs/ca-certificates.crt","CA_TRUSTANCHOR":"","FLEET_PROJECT_NUMBER":"438684899409","GCP_METADATA":"costin-asm1|438684899409|big1|us-central1-c","OUTPUT_CERTS":"/etc/istio/proxy","TRUST_DOMAIN":"costin-asm1.svc.id.goog","XDS_AUTH_PROVIDER":"gcp","XDS_ROOT_CA":"/etc/ssl/certs/ca-certificates.crt"},"meshId":"proj-438684899409"}
- ISTIO_META_WORKLOAD_NAME = based on deployment (fortio)
- ISTIO_META_OWNER =  kubernetes://apis/apps/v1/namespaces/fortio-asm/deployments/fortio
- ISTIO_META_MESH_ID - proj-438684899409 for ASM ( fleet project number )
- TRUST_DOMAIN - projectId.svc.id.goog
- CA_PROVIDER = GoogleCA for ASM
- CA_ROOT_CA,XDS_ROOT_CA=/etc/ssl/certs/ca-certificates.crt
- FLEET_PROJECT_NUMBER = project number
- GCP_METADATA costin-asm1|438684899409|big1|us-central1-c - Pipe separated GCP metadata, schemed as PROJECT_ID|PROJECT_NUMBER|CLUSTER_NAME|CLUSTER_ZONE
- XDS_AUTH_PROVIDER=gcp - use access tokens from the GCP SA using the project number
- ISTIO_META_CLUSTER_ID = cn-costin-asm1-us-central1-c-big1
- OUTPUT_CERTS = /etc/istio/proxy (The output directory for the key and certificate. If empty, key and certificate will not be saved. Must be set for VMs using provisioning certificates.)
- 
- "--domain" - defaults to $(POD_NAMESPACE).svc.cluster.local


Mounts:
- /var/run/secrets/workload-spiffe-credentials
- /var/run/secrets/istio - Istiod root cert, from configmap istio-ca-root-cert
- /var/lib/istio/data
- /var/run/secrets/tokens - istio-token volume, with audience = istio-ca
- /etc/istio/pod - pod info, via
 ``` downwardAPI: 
       items:
  - fieldRef:
  apiVersion: v1
  fieldPath: metadata.labels
  path: labels
  - fieldRef:
  apiVersion: v1
  fieldPath: metadata.annotations
  path: annotations
  ```

Unused/old configs:

- "--meshConfig PATH", defaults to ./etc/istio/config/mesh -
-  CERT_SIGNER_DOMAIN	String		The cert signer domain info
-  CLOUD_PLATFORM	String		Cloud Platform on which proxy is running, if not specified, Istio will try to discover the platform. Valid platform values are aws, azure, gcp, none
-  GCP_QUOTA_PROJECT	String		Allows specification of a quota project to be used in requests to GCP APIs.
-  GKE_CLUSTER_URL	String		The url of GKE cluster
-  ISTIOD_SAN	String		Override the ServerName used to validate Istiod certificate. Can be used as an alternative to setting /etc/hosts for VMs - discovery address will be an IP:port
-  ISTIO_DEFAULT_REQUEST_TIMEOUT	Time Duration	0s	Default Http and gRPC Request timeout
-  ISTIO_META_CERT_SIGNER	String		The cert signer info for workload cert
-  ISTIO_META_CLUSTER_ID	String
-  ISTIO_MULTIROOT_MESH	Boolean	false	If enabled, mesh will support certificates signed by more than one trustAnchor for ISTIO_MUTUAL mTLS
-  JWT_POLICY	String	third-party-jwt	The JWT validation policy.
-  KUBERNETES_SERVICE_HOST	String		Kubernetes service host, set automatically when running in-cluster
-  K_REVISION	String		KNative revision, set if running in knative
-  PROV_CERT	String		Set to a directory containing provisioned certs, for VMs. Location of provisioning
   certificates. VM provisioning tools must generate a certificate with
   the expected SAN. Istio-agent will use it to connect to istiod and get fresh certificates.
   /var/run/secrets/istio


Pilot env variables that may be shared:
-  TOKEN_AUDIENCES	String	istio-ca	A list of comma separated audiences to check in the JWT token before issuing a certificate. The token is accepted if it matches with one of the audiences. This is for Istiod.
-  TRUST_DOMAIN	String	cluster.local	The trust domain for spiffe certificates

In addition, VM sidecar.env defines:

- ISTIO_NAMESPACE=default -
- ISTIO_SVC_IP=IP - defaults to hostname --ip-address
- ISTIO_CFG=/var/lib/istio
```shell

# Location to save the certificates from the CA. Setting this to the same location with PROV_CERT
# allows rotation of the secrets. Users may also use longer-lived PROV_CERT, rotated under the control
# of the provisioning tool.
# Istiod may return a certificate with additional information and shorter lived, to be used for
# workload communication. In order to use the certificate with applications not supporting SDS, set this
# environment variable. If the value is different from PROV_CERTS the workload certs will be saved, but
# the provisioning cert will remain under control of the VM provisioning tools.
# OUTPUT_CERTS=/var/run/secrets/istio
# OUTPUT_CERTS=/etc/certs


```

