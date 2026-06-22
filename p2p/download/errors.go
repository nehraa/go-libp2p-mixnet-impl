package download

import "errors"

var (
	// ErrInvalidConfig indicates manager/service configuration validation failed.
	ErrInvalidConfig = errors.New("download: invalid config")
	// ErrInvalidRequest indicates request validation failed.
	ErrInvalidRequest = errors.New("download: invalid request")
	// ErrManifestInvalid indicates signed manifest validation failed.
	ErrManifestInvalid = errors.New("download: invalid signed manifest")
	// ErrShardIntegrity indicates shard bytes did not match manifest metadata.
	ErrShardIntegrity = errors.New("download: shard integrity check failed")
	// ErrDownloadTimeout indicates a shard request timed out.
	ErrDownloadTimeout = errors.New("download: shard download timeout")
	// ErrThresholdUnavailable indicates threshold mode was requested without a reconstructor.
	ErrThresholdUnavailable = errors.New("download: threshold reconstructor unavailable")
	// ErrHolderUnavailable indicates a shard holder rejected or could not serve a request.
	ErrHolderUnavailable = errors.New("download: shard holder unavailable")
)
