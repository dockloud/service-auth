package grpcauth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	serviceauth "github.com/dockloud/service-auth/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const DefaultMaxMessageBytes int64 = 10 << 20

func NewClientInterceptor(signer *serviceauth.Signer, maxMessageBytes int64) (grpc.UnaryClientInterceptor, error) {
	if signer == nil {
		return nil, errors.New("service auth: gRPC signer is required")
	}
	maxMessageBytes, err := normalizeMessageLimit(maxMessageBytes)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, method string, request, reply any, connection *grpc.ClientConn, invoker grpc.UnaryInvoker, options ...grpc.CallOption) error {
		message, err := marshalRequest(method, request, maxMessageBytes)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "service auth: cannot sign gRPC request: %v", err)
		}
		credentials, err := signer.Sign(ctx, message)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "service auth: cannot sign gRPC request: %v", err)
		}
		outgoing, _ := metadata.FromOutgoingContext(ctx)
		outgoing = outgoing.Copy()
		if outgoing == nil {
			outgoing = metadata.MD{}
		}
		setMetadata(outgoing, credentials)
		return invoker(metadata.NewOutgoingContext(ctx, outgoing), method, request, reply, connection, options...)
	}, nil
}

func NewServerInterceptor(verifier *serviceauth.Verifier, maxMessageBytes int64) (grpc.UnaryServerInterceptor, error) {
	if verifier == nil {
		return nil, errors.New("service auth: gRPC verifier is required")
	}
	maxMessageBytes, err := normalizeMessageLimit(maxMessageBytes)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		credentials, err := getMetadata(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "service authentication required")
		}
		message, err := marshalRequest(info.FullMethod, request, maxMessageBytes)
		if err != nil {
			if errors.Is(err, errMessageTooLarge) {
				return nil, status.Error(codes.ResourceExhausted, "service authentication message too large")
			}
			return nil, status.Error(codes.Internal, "service authentication could not inspect request")
		}
		principal, err := verifier.Verify(ctx, credentials, message)
		if err != nil {
			if errors.Is(err, serviceauth.ErrUnauthenticated) {
				return nil, status.Error(codes.Unauthenticated, "service authentication failed")
			}
			return nil, status.Error(codes.Internal, "service authentication service unavailable")
		}
		return handler(serviceauth.WithPrincipal(ctx, principal), request)
	}, nil
}

var errMessageTooLarge = errors.New("service auth: gRPC message exceeds configured limit")

func marshalRequest(method string, request any, maxMessageBytes int64) (serviceauth.Request, error) {
	if method == "" {
		return serviceauth.Request{}, serviceauth.ErrInvalidRequest
	}
	message, ok := request.(proto.Message)
	if !ok || message == nil {
		return serviceauth.Request{}, fmt.Errorf("unsupported gRPC request type %T", request)
	}
	value := reflect.ValueOf(message)
	if value.Kind() == reflect.Ptr && value.IsNil() {
		return serviceauth.Request{}, fmt.Errorf("unsupported gRPC request type %T", request)
	}
	body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return serviceauth.Request{}, err
	}
	if int64(len(body)) > maxMessageBytes {
		return serviceauth.Request{}, errMessageTooLarge
	}
	return serviceauth.Request{Method: "GRPC", Target: method, Body: body}, nil
}

func normalizeMessageLimit(maxMessageBytes int64) (int64, error) {
	if maxMessageBytes == 0 {
		return DefaultMaxMessageBytes, nil
	}
	if maxMessageBytes < 0 {
		return 0, errors.New("service auth: max message size must be positive")
	}
	return maxMessageBytes, nil
}

func setMetadata(md metadata.MD, credentials serviceauth.Credentials) {
	md.Set(strings.ToLower(serviceauth.HeaderKeyID), credentials.KeyID)
	md.Set(strings.ToLower(serviceauth.HeaderTimestamp), strconv.FormatInt(credentials.Timestamp, 10))
	md.Set(strings.ToLower(serviceauth.HeaderSignature), credentials.Signature)
}

func getMetadata(ctx context.Context) (serviceauth.Credentials, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return serviceauth.Credentials{}, serviceauth.ErrUnauthenticated
	}
	keyIDs := md.Get(strings.ToLower(serviceauth.HeaderKeyID))
	timestamps := md.Get(strings.ToLower(serviceauth.HeaderTimestamp))
	signatures := md.Get(strings.ToLower(serviceauth.HeaderSignature))
	if len(keyIDs) != 1 || len(timestamps) != 1 || len(signatures) != 1 {
		return serviceauth.Credentials{}, serviceauth.ErrUnauthenticated
	}
	timestamp, err := strconv.ParseInt(timestamps[0], 10, 64)
	if err != nil {
		return serviceauth.Credentials{}, serviceauth.ErrUnauthenticated
	}
	return serviceauth.Credentials{KeyID: keyIDs[0], Timestamp: timestamp, Signature: signatures[0]}, nil
}
