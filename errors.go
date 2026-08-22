package canonical

import "errors"

// Errors returned by every exported Marshal/Unmarshal in this package.
var (
	ErrVersion  = errors.New("canonical: unknown structure version")
	ErrTrailing = errors.New("canonical: trailing bytes after structure")
	// ErrNonCanonical rejects input that decodes but is not the encoding this package emits.
	ErrNonCanonical = errors.New("canonical: input is not the canonical encoding of its value")
	ErrRange        = errors.New("canonical: value out of representable range")
	ErrLength       = errors.New("canonical: fixed-width field has the wrong length")
	ErrEmpty        = errors.New("canonical: required field is empty")
	ErrFormat       = errors.New("canonical: field does not have its required value")
	ErrOrder        = errors.New("canonical: SEQUENCE OF is not sorted strictly ascending")
)
