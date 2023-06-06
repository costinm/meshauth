# Survey of identities

## Email address

This is the de-facto standard on the internet for users as well as 'service accounts'. Many tried to replace 
it with URLs, hostnames and other things - all failed.

## Public DNS 

This is the de-factor standard to identify hosts and services - backed by public certificates. 
Owner of the domain pays the registration and specify the authoritative DNS servers, which may delegate
subdomains to other DNS servers. Owner of the DNS controls the IPs mapped to each name, and control over
IP or DNS allows ACME to issue certificates to whoever controls the IP (enough to serve on a specific subdomain).

As a security warning - allowing users to define a HttpRoute under the challenge URL is also allowing them
to get certificates for the domain. 

## Layers, images and containers

Quoting from [containers/storage](https://github.com/containers/storage):

- layer is a copy-on-write filesystem (fragment) - we can think of it as a tar file, with references to a parent.
- image is a reference to a layer plus configuration - binary to run, env, etc
- container is a read-write layer, with a pointer to an image and additional configuration

All 3 are typically using a 32 char hex - or 16 bytes - identifier. The 32 byte container identifier is the
'canonical' ID on the VM or host where the container is running, it can also have friendly names. 


