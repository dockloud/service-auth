package httpauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	serviceauth "github.com/dockloud/service-auth/core"
)

type resolver map[string]serviceauth.Key

func (r resolver) ResolveKey(_ context.Context, keyID string) (serviceauth.Key, error) {
	key, ok := r[keyID]
	if !ok {
		return serviceauth.Key{}, serviceauth.ErrUnknownKey
	}
	return key, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestTransportSignsRequestAndMiddlewareExposesPrincipal(t *testing.T) {
	key := serviceauth.Key{ID: "caller-key", Service: "orders", Secret: []byte("0123456789abcdef0123456789abcdef")}
	signer, err := serviceauth.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := serviceauth.NewVerifier(resolver{key.ID: key}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var principal serviceauth.Principal
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, _ = serviceauth.PrincipalFromContext(request.Context())
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read downstream body: %v", err)
		}
		writer.Write(body)
	})
	middleware, err := NewMiddleware(verifier, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(middleware(handler))
	defer server.Close()
	transport, err := NewTransport(http.DefaultTransport, signer, 0)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport}
	response, err := client.Post(server.URL+"/v1/orders?expand=true", "text/plain", strings.NewReader("order-body"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	result, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(result) != "order-body" {
		t.Fatalf("unexpected response: status=%d body=%q", response.StatusCode, result)
	}
	if principal != (serviceauth.Principal{Service: key.Service, KeyID: key.ID}) {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestMiddlewareRejectsTamperedBody(t *testing.T) {
	key := serviceauth.Key{ID: "caller-key", Service: "orders", Secret: []byte("0123456789abcdef0123456789abcdef")}
	signer, err := serviceauth.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := serviceauth.NewVerifier(resolver{key.ID: key}, 0)
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := NewMiddleware(verifier, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader("original"))
	credentials, err := signer.Sign(request.Context(), serviceauth.Request{Method: request.Method, Target: request.URL.RequestURI(), Body: []byte("original")})
	if err != nil {
		t.Fatal(err)
	}
	setHeaders(request.Header, credentials)
	request.Body = io.NopCloser(strings.NewReader("tampered"))
	called := false
	response := httptest.NewRecorder()
	middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("tampered request was not rejected: status=%d called=%v", response.Code, called)
	}
}
