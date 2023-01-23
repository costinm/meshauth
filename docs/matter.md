# Matter certificates and auth

The Matter IOT standard defines a secure mesh similar to the cloud mesh and Istio. The standard
has several parts, some specific to modeling different types of devices and messages. 

It would be highly desirable for a mesh (fabric in Matter) could span both IoT devices 
and compute elements, including cloud. 

The matter fabric is based on an IPv6 overlay, with each workload or device having an 
'operational certificate' and all devices sharing a root CA which defines the fabric ID.

## Certificate format

Matter certificate is a true 'workload identity' - each workload or device has a unique certificate,
with well defined elements. 

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

matter-node-id - operational node ID, 64 bit
matter-firmware-signining-id
matter-icac-id - intermediary cert, 64 bit
matter-rcac-id - root cert, 64 bit 

Max 5 RDN per DN


## Root and intermediate






## Tools

cert-tool in Chip project provides some useful helpers.


