package canonical

import "errors"

// Errors returned by every exported Marshal/Unmarshal in this package.
var (
	ErrVersion  = errors.New("canonical: unknown structure version")
	ErrTrailing = errors.New("canonical: trailing bytes after structure")
	ErrRange    = errors.New("canonical: value out of representable range")
	ErrLength   = errors.New("canonical: fixed-width field has the wrong length")
)
