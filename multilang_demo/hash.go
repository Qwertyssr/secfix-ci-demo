package main

import (
	"crypto/md5"
	"fmt"
)

func fingerprint(data []byte) string {
	// VULN (Fortify: Weak Cryptographic Hash) -> should become sha256
	sum := md5.Sum(data)
	return fmt.Sprintf("%x", sum)
}
