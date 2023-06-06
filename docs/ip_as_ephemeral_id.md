# IP address as ephemeral identity proxy

## MDS

Most cloud platform support a 'metadata service', as well as 
secure VPC networks, where traffic is encrypted and the IP authenticated.

The MDS usually works by routing or redirecting traffic to a
specific link-local IP (169.254.169.254) for autoconfig.

For VMs this is also the DNS server, using domain 'ZONE.c.PROJECT_ID.internal'
and the vm name as hostname.

```shell
# GCP
`curl "http://metadata.google.internal/computeMetadata/v1/VM/service-accounts/123456789-compute%40developer.gserviceaccount.com/?query_path=https%3A%2F%2Flocalhost%3A8200%2Fexample%2Fquery&another_param=true" -H "Metadata-Flavor: Google"
`
# EC2
curl -s http://169.254.169.254/user-data/
```

How it works: this is usually a per host service ( it could also be a separate host 
in theory, if the VPC is secure), using routing or interception to get
the http traffic. 

No https encryption is used - it's a local host service.

The MDS uses the peer IP to lookup VM info and associated
service account, and has permissions to get credentials.
Usually the server issuing tokens/certs also checks that the
MDS server asking is on the same physical node or VM.

## Link local range

The first 256 and last 256 addresses in the range are reserved.
The MDS server address seems to violate this.

All other addresses can be allocated using rfc3927 if no DHCP
or manual address is available. Combined with mDNS or other 
discovery it can create a local network without infra.

In GKE default route can be 169.254.1.1

## Ztunnel

In Istio a similar mechanism is used - the per node ztunnel
gets the pod info based on peer IP, and looks up using XDS.

## Service IPs

In GKE, service VIP is will be in 34.118.224.0/20 range (public google IPs) - instead of 10.0.0.0/8 subnet,
i.e. 4K services max with ClusterIP.