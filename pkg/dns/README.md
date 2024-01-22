# DNS interface

This provides a mechanism to interact with the server using DNS TXT and regular records.

For an agent, DNS-over-UDP and over an L4 secure network - the DNS-over-TCP are secure for the workload to 
DNS communication. 

Over internet - DNS-over-TLs or DNS-over-HTTPS should be used instead, with an appropriate resolver.

TODO: sign the DNS records so DNS-over-UDP can also be used by clients with correct resolvers
TODO: verify DNS signature for agent to allow DNS-over-UDP.

## Client expectations

### Secure resolver

If the client includes a secure DNS resolver ( DNS over encrypted communication or signature verification), a central 
DNS server can be used. 

If the client only supports UDP (common case) and the cluster or VPC network UDP layer is trusted (wireguard, cloud
vendor native encryption) a server in the same cluster or VPC can be used.

If the client only supports UDP and the cluster network UDP is not trusted - a per-node agent is required.

## Data

The exposed data is the same 'mesh' metadata that the meshauth package is tracking.

The mapping is:

- DNS zone is the FQDN of the meshauth server.
- PTR records provided for all known IPs
- {MANGLED_IP}.ip.{ZONE} TXT records
- {SERVICE}.{ZONE} TXT and A records
