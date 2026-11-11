package serviceauth

import "context"

const (
	HeaderKeyID     = "X-Service-Auth-Key-Id"
	HeaderTimestamp = "X-Service-Auth-Timestamp"
	HeaderSignature = "X-Service-Auth-Signature"
)

type Key struct {
	ID      string
	Service string
	Secret  []byte
}

type Principal struct {
	Service string
	KeyID   string
}

type KeyResolver interface {
	ResolveKey(ctx context.Context, keyID string) (Key, error)
}

type Request struct {
	Method string
	Target string
	Body   []byte
}

type Credentials struct {
	KeyID     string
	Timestamp int64
	Signature string
}

type principalContextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}
