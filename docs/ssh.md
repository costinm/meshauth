# SSH and Mesh authentication

SSH also uses keys and supports certificates, but in a different format. 
It is very common to upload the public key from a machine to Github or add it
to authorized_keys on cloud VMs to allow access. 

https://security.stackexchange.com/questions/226576/certificate-used-in-ssl-and-keys-used-in-ssh

While it is a bad practice to reuse bearer tokens - the model for workload identity
is that a Pod or VM have one identity represented by private key and certificates.
If using a different private key for each protocol is acceptable - using it for 
ssh doesn't seem different.

The problem is converting the key format and getting certificates for SSH.

There are 2 ways to do this, one is starting with workload identity and converting
it to SSH, the other is generating SSH keys and getting certificates for them.

This package will check the .ssh directory and attempt to use id_ecdsa SSH key, 
which uses the same format. Will also use that directory for all local key storage.
A separate ssh-mesh package will handle/convert the other ssh configs. 

Short summary:

```shell

ssh-keygen -t ecdsa -f ~/.ssh/ca_key

# User certificate - use FQDN of the host for both
ssh-keygen -s ca_key -I $(FQDN) -n ${KSA}.${NAMESPACE} id_ecdsa.pub

# Host certificate
ssh-keygen -s ca_key -I ${FQDN} -n ${FQDN} -h /etc/ssh/ssh_host_ecdsa_key.pub

# -n principal,principal2 - multiple identities to include
# -V validity

```

ssh-keygen also allows sign/verify arbitrary files.

## Storage

With ssh it is more common to use an agent and to encrypt the keys on a dev machine.
On physical machines - TPMs can be used to protect the private key. 

Having long-lived private keys is common practice for SSH without certificates, 
since it's very hard to upload the public key in all places. If a mesh-like
rotation is used - it would use a root certificate for SSH and that will be 
distributed.

TODO: which services support configuring a SSH root ? 

## Limitations for SSH

Main limitation is that SSH doesn't support intermediate certificates. 

The format and signing are different - but that can be handled with code.
