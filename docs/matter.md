# Matter certificates and auth

The Matter IoT standard defines a secure mesh similar to the cloud mesh and Istio. The standard
has several parts, some specific to modeling different types of devices and messages. 

It would be highly desirable for a mesh (fabric in Matter) could span both IoT devices 
and compute elements, including cloud. 

The matter fabric is based on an IPv6 overlay, with each workload or device having an 
'operational certificate' and all devices sharing a root CA which defines the fabric ID.

## Matter and GAMMA (Istio or others)

Matter defines 2 key elements for the certificate: the node ID and fabric ID, both 64bit. 



## Certificate format

Matter certificate is a true 'workload identity' - each workload or device has a unique certificate,
with well-defined elements. 

The standard defines a set of 'commissioning' methods well suited for consumer devices, but 
leaves the door open for others. The end result is having each device/workload receive a 
node (workload in case of mesh) operational certificate - NOC.

There is also a custom format (alternative to PEM, using matter TLV) - may be useful for 
some low end devices but not relevant for higher end and workloads. Also it is not clear why 
it is defined - the signature is over the DER representation, so it doesn't even avoid the need
for ASN.1 dependency. Might be some legacy from older standards, appears safe to mostly ignore.

What is relevant for mesh is the information included:

```text
Certificate Text
 Version Number - v3
 Serial Number - up to 20 octets
 Signature Algorithm ID - 1.2.840.10045.4(signatures).ecdsa-with-SHA2(3).ecdsawith-SHA256(2)
 Issuer Name -  DN
 Subject Name - DN
 Validity period
   Not Before
   Not After - 0 means undefined
 Subject Public Key Info
   Public Key Algorithm - ec256
   Subject Public Key 
 Issuer Unique Identifier
 Subject Unique Identifier
 Extensions
Certificate Signature Algorithm
Certificate Signature

```

The DN is encoded as UTF8, except domain component.

matter-node-id - operational node ID, 64 bit - 1.3.6.1.4.1.37244.1.1
fabric-id - 1.3.6.1.4.1.37244.1.5
matter-firmware-signining-id
matter-icac-id - intermediary cert, 64 bit - 1.3.6.1.4.1.37244.1.3
matter-rcac-id - root cert, 64 bit - 1.3.6.1.4.1.37244.1.4

Max 5 RDN per DN


## Root and intermediate






## Tools

cert-tool in Chip project provides some useful helpers.

## Access control

Default is deny.  Subjects are granted specific permissions to targets in the node. This generally maps to ports in mesh. The permission include the concept and separate value of 'Proxy-View',
in addition to View/Operate(write+invoke)/Manage(config data change and ops)/Administer.

The role of 'viewer', 'proxy-viewer' (Waypoing or ingress/egress in mesh), Operate, Manage and
Admin is fixed but seems more clear than the K8S or Istio RBAC models. 

The node can be part of multiple fabrics (meshes) - so each ACL includes the fabric ID.
( TODO: separate doc describing Matter multi-mesh approach and how to use it in Istio).

The source is identified by a node ID (pod to pod) or by a 'CASE authenticated tag'. It can
also be a group, using 'operational group key'.

CASE tag (CAT) is a special DN part of the certificate (max 2?), acting like a group. This may
be mapped to mesh service accounts or special k8s labels.

CAN has 16 bit ID and 16 bit version, mapped to a 64 bit node ID with FFFF:FFFD prefix.







