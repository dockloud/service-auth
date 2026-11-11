package serviceauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const DefaultClockSkew = 5 * time.Minute

type Verifier struct {
	resolver     KeyResolver
	maxClockSkew time.Duration
	clock        func() time.Time
}

func NewVerifier(resolver KeyResolver, maxClockSkew time.Duration) (*Verifier, error) {
	if resolver == nil {
		return nil, errors.New("service auth: key resolver is required")
	}
	if maxClockSkew == 0 {
		maxClockSkew = DefaultClockSkew
	}
	if maxClockSkew < 0 {
		return nil, errors.New("service auth: max clock skew must not be negative")
	}
	return &Verifier{resolver: resolver, maxClockSkew: maxClockSkew, clock: time.Now}, nil
}

func (v *Verifier) Verify(ctx context.Context, credentials Credentials, request Request) (Principal, error) {
	if err := validateRequest(request); err != nil {
		return Principal{}, err
	}
	if credentials.KeyID == "" || credentials.Timestamp <= 0 || credentials.Signature == "" {
		return Principal{}, unauthenticated(ErrInvalidSignature)
	}
	if delta := v.clock().Sub(time.Unix(credentials.Timestamp, 0)); delta > v.maxClockSkew || delta < -v.maxClockSkew {
		return Principal{}, unauthenticated(ErrStaleTimestamp)
	}

	key, err := v.resolver.ResolveKey(ctx, credentials.KeyID)
	if err != nil {
		if errors.Is(err, ErrUnknownKey) {
			return Principal{}, unauthenticated(ErrUnknownKey)
		}
		return Principal{}, fmt.Errorf("service auth: resolve key: %w", err)
	}
	if err := validateKey(key); err != nil || key.ID != credentials.KeyID {
		return Principal{}, fmt.Errorf("service auth: resolver returned invalid key for %q: %w", credentials.KeyID, ErrInvalidKey)
	}

	provided, err := base64.RawURLEncoding.DecodeString(credentials.Signature)
	if err != nil {
		return Principal{}, unauthenticated(ErrInvalidSignature)
	}
	mac := hmac.New(sha256.New, key.Secret)
	writeCanonical(mac, key.ID, credentials.Timestamp, request)
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return Principal{}, unauthenticated(ErrInvalidSignature)
	}
	return Principal{Service: key.Service, KeyID: key.ID}, nil
}

func unauthenticated(reason error) error {
	return fmt.Errorf("%w: %w", ErrUnauthenticated, reason)
}
