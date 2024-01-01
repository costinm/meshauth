package meshauth

import (
	"crypto/x509"
	"errors"
	"log"
	"net/http"
)

func (d *Dest) GetCACertPEM() []byte {
	return d.CACertPEM
}

func (c *Dest) AddToken(ma *MeshAuth, req *http.Request, aut string) error {
	if c.TokenSource != "" {
		tp := ma.AuthProviders[c.TokenSource]
		if tp != nil {
			t, err := tp.GetToken(req.Context(), aut)
			if err != nil {
				return err
			}
			req.Header.Add("authorization", "Bearer "+t)
		}
	}
	if c.TokenProvider != nil {
		t, err := c.TokenProvider.GetRequestMetadata(req.Context(), aut)
		if err != nil {
			return err
		}
		for k, v := range t {
			req.Header.Add(k, v)
		}
	}

	if c.Token != "" {
		req.Header.Add("authorization", c.Token)
	}
	return nil
}

func (d *Dest) CertPool() *x509.CertPool {
	if d.roots == nil {
		d.roots = x509.NewCertPool()
		if d.CACertPEM != nil {
			ok := d.roots.AppendCertsFromPEM(d.CACertPEM)
			if !ok {
				log.Println("Failed to parse CACertPEM", "addr", d.Addr)
			}
		}
	}
	return d.roots
}

func (d *Dest) AddCACertPEM(pems []byte) error {
	if d.roots == nil {
		d.roots = x509.NewCertPool()
	}
	if d.CACertPEM != nil {
		d.CACertPEM = append(d.CACertPEM, '\n')
		d.CACertPEM = append(d.CACertPEM, pems...)
	} else {
		d.CACertPEM = pems
	}
	if !d.roots.AppendCertsFromPEM(pems) {
		return errors.New("Failed to decode PEM")
	}
	return nil
}
