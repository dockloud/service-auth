package serviceauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"strconv"
	"time"
)

const signatureDomain = "dockloud-service-auth:v1\x00"

type Signer struct {
	key   Key
	clock func() time.Time
}

func NewSigner(key Key) (*Signer, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	return &Signer{key: cloneKey(key), clock: time.Now}, nil
}

func (s *Signer) Sign(_ context.Context, request Request) (Credentials, error) {
	if err := validateRequest(request); err != nil {
		return Credentials{}, err
	}
	timestamp := s.clock().Unix()
	mac := hmac.New(sha256.New, s.key.Secret)
	writeCanonical(mac, s.key.ID, timestamp, request)
	return Credentials{
		KeyID:     s.key.ID,
		Timestamp: timestamp,
		Signature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}, nil
}

func validateRequest(request Request) error {
	if request.Method == "" || request.Target == "" {
		return ErrInvalidRequest
	}
	return nil
}

func validateKey(key Key) error {
	if key.ID == "" || key.Service == "" || len(key.Secret) < 32 {
		return ErrInvalidKey
	}
	return nil
}

func cloneKey(key Key) Key {
	key.Secret = append([]byte(nil), key.Secret...)
	return key
}

func writeCanonical(mac hash.Hash, keyID string, timestamp int64, request Request) {
	_, _ = mac.Write([]byte(signatureDomain))
	writeField(mac, keyID)
	writeField(mac, strconv.FormatInt(timestamp, 10))
	writeField(mac, request.Method)
	writeField(mac, request.Target)
	bodyHash := sha256.Sum256(request.Body)
	writeField(mac, string(bodyHash[:]))
}

func writeField(mac hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write([]byte(value))
}
