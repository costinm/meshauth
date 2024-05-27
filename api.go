package meshauth

// Authentication:
// 1. client configs specific to how to talk to a destination. Include
//   client certs, secrets, token sources. Attached to a host (xds_cluster)
//   or default per gateway
// 2. client config - how to validate a server - per host (xds_cluster) or
//   default per gateway
// 3. server config - certificates for port and SNI. Per listener or default.
// 4. server config - how to validate clients. Per listener or default.
//
// 2 and 4 have common config for cert based. We can also treat JWT as signed.
//
//
