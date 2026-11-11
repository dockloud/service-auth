package httpauth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	serviceauth "github.com/dockloud/service-auth/core"
)

const DefaultMaxBodyBytes int64 = 10 << 20

var errBodyTooLarge = errors.New("service auth: request body exceeds configured limit")

type Transport struct {
	base         http.RoundTripper
	signer       *serviceauth.Signer
	maxBodyBytes int64
}

func NewTransport(base http.RoundTripper, signer *serviceauth.Signer, maxBodyBytes int64) (*Transport, error) {
	if signer == nil {
		return nil, errors.New("service auth: HTTP signer is required")
	}
	maxBodyBytes, err := normalizeBodyLimit(maxBodyBytes)
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &Transport{base: base, signer: signer, maxBodyBytes: maxBodyBytes}, nil
}

func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := readBody(request.Body, t.maxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("service auth: read HTTP request body: %w", err)
	}
	if request.URL == nil {
		return nil, serviceauth.ErrInvalidRequest
	}
	message := serviceauth.Request{
		Method: request.Method,
		Target: request.URL.RequestURI(),
		Body:   body,
	}
	credentials, err := t.signer.Sign(request.Context(), message)
	if err != nil {
		return nil, fmt.Errorf("service auth: sign HTTP request: %w", err)
	}

	signed := request.Clone(request.Context())
	signed.Body = io.NopCloser(bytes.NewReader(body))
	signed.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	signed.ContentLength = int64(len(body))
	signed.Header = request.Header.Clone()
	if signed.Header == nil {
		signed.Header = make(http.Header)
	}
	setHeaders(signed.Header, credentials)
	return t.base.RoundTrip(signed)
}

func NewMiddleware(verifier *serviceauth.Verifier, maxBodyBytes int64) (func(http.Handler) http.Handler, error) {
	if verifier == nil {
		return nil, errors.New("service auth: HTTP verifier is required")
	}
	maxBodyBytes, err := normalizeBodyLimit(maxBodyBytes)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			credentials, err := getHeaders(request.Header)
			if err != nil {
				http.Error(writer, "unauthorized", http.StatusUnauthorized)
				return
			}
			body, err := readBody(request.Body, maxBodyBytes)
			if err != nil {
				if errors.Is(err, errBodyTooLarge) {
					http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
				} else {
					http.Error(writer, "could not read request body", http.StatusBadRequest)
				}
				return
			}
			if request.URL == nil {
				http.Error(writer, "invalid request", http.StatusBadRequest)
				return
			}
			request.Body = io.NopCloser(bytes.NewReader(body))
			principal, err := verifier.Verify(request.Context(), credentials, serviceauth.Request{
				Method: request.Method,
				Target: request.URL.RequestURI(),
				Body:   body,
			})
			if err != nil {
				if errors.Is(err, serviceauth.ErrUnauthenticated) {
					http.Error(writer, "unauthorized", http.StatusUnauthorized)
				} else {
					http.Error(writer, "authentication service unavailable", http.StatusInternalServerError)
				}
				return
			}
			next.ServeHTTP(writer, request.WithContext(serviceauth.WithPrincipal(request.Context(), principal)))
		})
	}, nil
}

func normalizeBodyLimit(maxBodyBytes int64) (int64, error) {
	if maxBodyBytes == 0 {
		return DefaultMaxBodyBytes, nil
	}
	if maxBodyBytes < 0 || maxBodyBytes == int64(^uint64(0)>>1) {
		return 0, errors.New("service auth: max body size must be positive and finite")
	}
	return maxBodyBytes, nil
}

func readBody(body io.ReadCloser, maxBodyBytes int64) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	defer body.Close()
	contents, err := io.ReadAll(io.LimitReader(body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maxBodyBytes {
		return nil, errBodyTooLarge
	}
	return contents, nil
}

func setHeaders(header http.Header, credentials serviceauth.Credentials) {
	header.Set(serviceauth.HeaderKeyID, credentials.KeyID)
	header.Set(serviceauth.HeaderTimestamp, strconv.FormatInt(credentials.Timestamp, 10))
	header.Set(serviceauth.HeaderSignature, credentials.Signature)
}

func getHeaders(header http.Header) (serviceauth.Credentials, error) {
	keyIDs := header.Values(serviceauth.HeaderKeyID)
	timestamps := header.Values(serviceauth.HeaderTimestamp)
	signatures := header.Values(serviceauth.HeaderSignature)
	if len(keyIDs) != 1 || len(timestamps) != 1 || len(signatures) != 1 {
		return serviceauth.Credentials{}, serviceauth.ErrUnauthenticated
	}
	timestamp, err := strconv.ParseInt(timestamps[0], 10, 64)
	if err != nil {
		return serviceauth.Credentials{}, serviceauth.ErrUnauthenticated
	}
	return serviceauth.Credentials{KeyID: keyIDs[0], Timestamp: timestamp, Signature: signatures[0]}, nil
}
