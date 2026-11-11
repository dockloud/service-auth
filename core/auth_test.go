package serviceauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testResolver map[string]Key

func (r testResolver) ResolveKey(_ context.Context, keyID string) (Key, error) {
	key, ok := r[keyID]
	if !ok {
		return Key{}, ErrUnknownKey
	}
	return key, nil
}

func TestSignAndVerify(t *testing.T) {
	key := Key{ID: "caller-key", Service: "billing", Secret: []byte("0123456789abcdef0123456789abcdef")}
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(testResolver{key.ID: key}, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Method: "POST", Target: "/v1/payments?dry_run=false", Body: []byte("payload")}
	credentials, err := signer.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}

	principal, err := verifier.Verify(context.Background(), credentials, request)
	if err != nil {
		t.Fatal(err)
	}
	if principal != (Principal{Service: key.Service, KeyID: key.ID}) {
		t.Fatalf("unexpected principal: %#v", principal)
	}

	request.Body = []byte("changed")
	if _, err := verifier.Verify(context.Background(), credentials, request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected unauthenticated error, got %v", err)
	}
}

func TestVerifyRejectsUnknownAndStaleCredentials(t *testing.T) {
	key := Key{ID: "known", Service: "caller", Secret: []byte("0123456789abcdef0123456789abcdef")}
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(testResolver{key.ID: key}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Method: "GET", Target: "/status"}
	credentials, err := signer.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	credentials.KeyID = "unknown"
	if _, err := verifier.Verify(context.Background(), credentials, request); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected unknown key to be unauthenticated, got %v", err)
	}

	credentials.KeyID = key.ID
	credentials.Timestamp = 1
	if _, err := verifier.Verify(context.Background(), credentials, request); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("expected stale timestamp error, got %v", err)
	}
}

func TestNewSignerRequiresStrongKey(t *testing.T) {
	_, err := NewSigner(Key{ID: "weak", Service: "caller", Secret: []byte("short")})
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected invalid key error, got %v", err)
	}
}
