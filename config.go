package tus

import (
	"log"
	"os"
)

// Config provides a way to configure the Client depending on your needs.
type Config struct {
	// ChunkSize divide the file into chunks.
	ChunkSize int64
	// Resume enables resumable upload.
	Resume bool
	// OverridePatchMethod allow to by pass proxies sendind a POST request instead of PATCH.
	OverridePatchMethod bool
	// Store map an upload's fingerprint with the corresponding upload URL.
	// If Resume is true the Store is required.
	Store Store
	// Logger is the logger to use internally, mostly for upload progress.
	Logger *log.Logger
}

// DefaultConfig return the default Client configuration.
func DefaultConfig() *Config {
	return &Config{
		ChunkSize:           2 * 1024 * 1024,
		Resume:              false,
		OverridePatchMethod: false,
		Store:               nil,
		Logger:              log.New(os.Stdout, "[tus] ", 0),
	}
}

// Validate validates the custom configuration.
func (c *Config) Validate() error {
	if c.ChunkSize < 1 {
		return ErrChuckSize
	}

	if c.Logger == nil {
		return ErrNilLogger
	}

	if c.Resume && c.Store == nil {
		return ErrNilStore
	}

	return nil
}