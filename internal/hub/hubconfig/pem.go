package hubconfig

import "encoding/pem"

type pemBlock = pem.Block

// nextCert returns the next CERTIFICATE block in data and the remainder.
func nextCert(data []byte) (*pemBlock, []byte) {
	for {
		var b *pem.Block

		b, data = pem.Decode(data)
		if b == nil {
			return nil, nil
		}

		if b.Type == "CERTIFICATE" {
			return b, data
		}
	}
}
