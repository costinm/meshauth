package meshauth


type CAConfig struct {
	// TrustDomain to use in certs.
	// Should not be 'cluster.local' - but a real FQDN
	TrustDomain string

	// Location of the CA root - currently a dir path.
	//
	RootLocation string

	// TODO: additional configs/policies.
}

