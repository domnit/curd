//go:build !darwin

package chrome

// KeychainProvider returns the production key provider. On Linux only
// Chrome's basic password store (--password-store=basic, password "peanuts")
// is supported; rows encrypted with a libsecret/kwallet key (v11) cannot be
// decrypted and produce a clear error.
func KeychainProvider() KeyProvider {
	return staticProvider{name: "basic-store", passwords: []string{"peanuts"}, iters: 1}
}
