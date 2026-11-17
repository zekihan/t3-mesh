package hubconfig

import "encoding/pem"

type pemBlock = pem.Block

// nextCert returns the next CERTIFICATE block in data and the remainder.
func nextCert(data []byte) (*pemBlock, []byte) {
	for {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			return nil, nil
		}

		if block.Type == "CERTIFICATE" {
			return block, data
		}
	}
}
