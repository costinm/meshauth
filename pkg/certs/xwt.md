# X509 Web Tokens

## Background

This is not a joke. It may have started at one, but it was as funny as all the other token formats.

For a new authentication scheme, we generally need:

- a new name - XWT 
- a new encoding format - WebDER
- a new way to name different common concepts and field - WebSAN and WebSubject

All authentication schems are based on signatures or shared secrets - and work the same, so we need to differentiate. Sometimes a new protocol or application that only works with the new scheme, or extensive marketing also helps - but this spec will have to rely on cosmetic differences.

## WebDER format

The XWT tokens are encoded in the WebDER format, which is identical to the subset of DER used in TLS. 

The format is similar to a 'binary JSON', like CBOR. It encodes byte sequences,
ints, lists.

As we know, the DER format has many flaws - which led to the lackluster adoption (rarely used protocols like TLS or HTTPS) and the development of many better encodings. WebDER solves this problem by using a new name and not mentioning ASN.1 or any of the other complexities that plague TLS.

The format is a TLV (tag, length, value).

The tags used:
- 30 SEQUENCE ( or list ) - followed by the length in bytes of the content and more TLVs
- 02 INTEGER
- 04 OCTET STRING - '
- 03 BIT STRING - used for signature, followed by the length in bytes and 1 byte for 'unused bits

Int and length encoding:
- 1 byte for len <127
- 0x80 | LEN of the int, followed by LEN bytes.

## Token format

An XWT consists of a list:
- 'Signed Data', or 'content' - type bytes
- 'Signature' MUST use ecdsa-with-SHA256 or ed25519-with-SHA256.

The encoding is typically a single WebCertificate in WebDER format, but it can
be content in any format - including not WebDER - that is signed. 

Like JWT, an XWT will be encoded in Base64-url when used in URLs or Authorization headers, but should be sent as binary if possible (for
example in binary http/2 headers).

Example Signed Data:
 30 - prefix
 VARINT - lentgh of the signed data - Example: 03, 81 xx, 82 xx xx 
 DATA[VARINT] - signed bytes

Example signature - last 88 bytes.
 30 0a - SEQUENCE, 10 bytes
  06 08 - OID of 8 bytes
   2a 86 48 ce 3d 04 03 02 - the identifier for ecdsa-with-SHA256
 03 49 00 - BIT string, 0x49 bytes, 0 unused bits
  30 46 - SEQUENCE, lenth is 0x46 bytes
   02 21 - prefix for R param of the signature (INTEGER, 33 bytes, 0 prefix)
    33 bytes - R with 0 prefix
   02 21 - prefix for the S param of the signature
    33 bytes - S with 00 prefix


# Claims

By default, the 'content' field of a XWT is in the WebCertificate format.
( == identical a bit level to a X.509 certificate ).

The 'content' can be anything else - if the token is sent along with additional
information about the 'issuer' (a FQDN), key id (optional), and the content type. An alternative including arbitrary content is to use the WebCertificate
format with a 'content' field.

## WebCertificate


## WebSubject 

The 'WebSubject' is used to indicate what is certified - in the case of a XWT it is not a user, but the association between the user and 
a service (or peer).

The identity of the user is provided in the SAN fields, and is not included in the WebSubject.

WebSubject is encoded in the Subject field of the certificate, using "O" to identify the organization for which the cert has been issued, and has the same semantics as the "aud" field in JWT.

While leaving the subject blank and use an X509 extension is also possible - it would be more complicated ( custom libraries, more complex code, assigning a new extension ID). It may be a good way to 'differentiate' and make XWT 
seem more 'secure' or smarter, like many other auth standards - but we can already differentiate enough by using the new made-up names.

## SANs

## Content

Arbitrary content can be signed in the certificate, using a new ID. (TBD)


# Identities

Like ATproto and DID:web - the primary identity is a FQDN. Unlike DID:web, there is no prefix for cosmetic differences.

All identities are encoded as:
- SAN fields in the WebCertificate - the primary identity should be first.
- CN fields in the 'Subject' and 'Issuer' fields of the WebCertificate 
- OU field in Subject - indicates the peer (audience)

The Issuer identifies the organization that signed the certificate, the 
Subject represents the service that is subject of the certificate, and the 
first SAN field should be the primary identity of the client. 

To make things more complicated, it is possible to encode the audience as a 
separate 'extension field', with a new OID (TBD).



# XWT issuance and verification


Any identity provider, CA or holder of a private key can issue a XWT by signing the WebCert.

The issuer must have a FQDN (can be .internal or .local) or URL, which
should be associated with the public key.

To get the public key:
- the issuer domain is used with one of the existing protocol ( web-did, JWK, etc )
- standard DNS TXT records
- the certificate used in the domain HTTPs service - when the XWT is issued using the 'workload key' (the private key used in the certificate).


## Mesh identity 

Since each auth scheme needs to differentiate by inventing a new and unusual identity format, the XWT defines an optional identity:

  PUB_KEY_SHA.m.SUFFIX
  
The PUB_KEY_SHA is the base32 encoded SHA(public key) or ED25519 public key.

The ".m." subdomain must be the second part of the FQDN. Implementations may use other values.

The SUFFIX is any FQDN, including .local or .internal. 

## Tools and libraries

To view an XWT containing a WebCert: 
  
  `openssl x509 -in FILE.der -inform der -text -noout'


# Relation with mTLS

The motivation for this doc was the frustration with the many 'token' formats
and similar balkanization of mTLS. The XWT is binary compatible X.509/DER and
the certificates used for TLS and mTLS, allowing the reuse of common code and
consistency.

In the case of mTLS, the 'certificate' is used to prove the association of 
an identity with a public key, which is used to sign a connection-specific 
challenge, in conjunction with a DH exchange. This works great for connections.


