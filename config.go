package tus

import (
	"net/http"
)

// Config provides a way to configure the Client depending on your needs.
type Config struct {
	// ChunkSize divide the file into chunks.
	ChunkSize int64
	// Resume enables resumable upload.
	Resume bool
	// OverridePatchMethod allow to by pass proxies sending a POST request instead of PATCH.
	OverridePatchMethod bool
	// OverrideCreatePostMethod allow sending a PATCH request instead of POST for a create request.
	OverrideCreatePostMethod bool
	// Store map an upload's fingerprint with the corresponding upload URL.
	// If Resume is true the Store is required.
	Store Store
	// Set custom header values used in all requests.
	Header http.Header
	// HTTP Client
	HttpClient *http.Client
	// Set checksum algorithm used in all requests.
	ChecksumAlgorithm ChecksumAlgorithm
}

// DefaultConfig return the default Client configuration.
func DefaultConfig() *Config {
	return &Config{
		ChunkSize:                2 * 1024 * 1024,
		Resume:                   false,
		OverrideCreatePostMethod: false,
		OverridePatchMethod:      false,
		Store:                    nil,
		Header:                   make(http.Header),
		HttpClient:               nil,
	}
}

// Validate validates the custom configuration.
func (c *Config) Validate() error {
	if c.ChunkSize < 1 {
		return ErrChuckSize
	}

	if c.Resume && c.Store == nil {
		return ErrNilStore
	}

	return nil
}

type ChecksumAlgorithm string

func (c ChecksumAlgorithm) String() string {
	return string(c)
}

const (
	EDLS   ChecksumAlgorithm = "edls"
	MD5    ChecksumAlgorithm = "md5"
	SHA1   ChecksumAlgorithm = "sha1"
	SHA256 ChecksumAlgorithm = "sha256"
)
