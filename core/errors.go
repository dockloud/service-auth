package serviceauth

import "errors"

var (
	ErrUnknownKey       = errors.New("service auth: unknown key")
	ErrInvalidKey       = errors.New("service auth: invalid key")
	ErrUnauthenticated  = errors.New("service auth: unauthenticated")
	ErrInvalidSignature = errors.New("service auth: invalid signature")
	ErrStaleTimestamp   = errors.New("service auth: timestamp outside allowed window")
	ErrInvalidRequest   = errors.New("service auth: invalid request")
)
