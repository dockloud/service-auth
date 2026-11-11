package grpcauth

import (
	"context"
	"testing"

	serviceauth "github.com/dockloud/service-auth/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type resolver map[string]serviceauth.Key

func (r resolver) ResolveKey(_ context.Context, keyID string) (serviceauth.Key, error) {
	key, ok := r[keyID]
	if !ok {
		return serviceauth.Key{}, serviceauth.ErrUnknownKey
	}
	return key, nil
}

func TestUnaryInterceptorsAuthenticateCaller(t *testing.T) {
	key := serviceauth.Key{ID: "caller-key", Service: "orders", Secret: []byte("0123456789abcdef0123456789abcdef")}
	signer, err := serviceauth.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := serviceauth.NewVerifier(resolver{key.ID: key}, 0)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientInterceptor(signer, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerInterceptor(verifier, 0)
	if err != nil {
		t.Fatal(err)
	}
	var principal serviceauth.Principal
	err = client(context.Background(), "/orders.v1.OrderService/Get", wrapperspb.String("request"), &wrapperspb.StringValue{}, nil,
		func(ctx context.Context, method string, request, reply any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			outgoing, _ := metadata.FromOutgoingContext(ctx)
			serverContext := metadata.NewIncomingContext(context.Background(), outgoing)
			_, err := server(serverContext, request, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ any) (any, error) {
				principal, _ = serviceauth.PrincipalFromContext(ctx)
				return nil, nil
			})
			return err
		})
	if err != nil {
		t.Fatal(err)
	}
	if principal != (serviceauth.Principal{Service: key.Service, KeyID: key.ID}) {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestUnaryInterceptorsRejectTamperedRequest(t *testing.T) {
	key := serviceauth.Key{ID: "caller-key", Service: "orders", Secret: []byte("0123456789abcdef0123456789abcdef")}
	signer, err := serviceauth.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := serviceauth.NewVerifier(resolver{key.ID: key}, 0)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientInterceptor(signer, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerInterceptor(verifier, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = client(context.Background(), "/orders.v1.OrderService/Get", wrapperspb.String("original"), &wrapperspb.StringValue{}, nil,
		func(ctx context.Context, method string, request, reply any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			outgoing, _ := metadata.FromOutgoingContext(ctx)
			serverContext := metadata.NewIncomingContext(context.Background(), outgoing)
			request.(*wrapperspb.StringValue).Value = "tampered"
			_, err := server(serverContext, request, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) { return nil, nil })
			return err
		})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated status, got %v", err)
	}
}
