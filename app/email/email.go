package email

import (
	"context"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"

	emailProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_email_service"
	"go.uber.org/zap"
)

// Env - email environment variables.
type Env struct {
	IP   string
	Port string
}

// GetEmailEnv - returns the environment of email service.
func GetEmailEnv() (*Env, error) {
	ip, check := os.LookupEnv("EMAIL_SERVICE_IP")
	if !check {
		return nil, errors.New("Required EMAIL_SERVICE_IP")
	}
	port, check := os.LookupEnv("EMAIL_SERVICE_PORT")
	if !check {
		return nil, errors.New("Required EMAIL_SERVICE_PORT")
	}
	return &Env{ip, port}, nil
}

// NewEmailClient - creates a connection to a email service.
func NewEmailClient(ctx context.Context, zapLog *zap.Logger, uri string) (*emailProto.EmailServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.DialContext(context.Background(), uri, grpc.WithInsecure())
	if err != nil {
		zapLog.Error(fmt.Sprintf("Could not dial email service with err %v", err))
		return nil, nil, err
	}

	emailClient := emailProto.NewEmailServiceClient(conn)

	_, err = emailClient.Ping(context.Background(), &emailProto.Request{})

	if err != nil {
		zapLog.Error(fmt.Sprintf("Could not ping email service with err %v", err))
		return &emailClient, nil, err
	}

	return &emailClient, conn, err
}
