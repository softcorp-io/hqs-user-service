package privilege

import (
	"context"
	"errors"
	"fmt"
	"os"

	privilegeProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_privilege_service"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Env - privilege environment variables.
type Env struct {
	IP   string
	Port string
}

// GetPrivilegeEnv - returns the environment of privilege service.
func GetPrivilegeEnv() (*Env, error) {
	ip, check := os.LookupEnv("PRIVILEGE_SERVICE_IP")
	if !check {
		return nil, errors.New("Required PRIVILEGE_SERVICE_IP")
	}
	port, check := os.LookupEnv("PRIVILEGE_SERVICE_PORT")
	if !check {
		return nil, errors.New("Required PRIVILEGE_SERVICE_PORT")
	}
	return &Env{ip, port}, nil
}

// NewPrivilegeClient - creates a connection to a privilege service.
func NewPrivilegeClient(ctx context.Context, zapLog *zap.Logger, uri string) (*privilegeProto.PrivilegeServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.DialContext(context.Background(), uri, grpc.WithInsecure())
	if err != nil {
		zapLog.Error(fmt.Sprintf("Could not dial privilege service with err %v", err))
		return nil, nil, err
	}

	privilegeClient := privilegeProto.NewPrivilegeServiceClient(conn)

	_, err = privilegeClient.Ping(context.Background(), &privilegeProto.Request{})

	if err != nil {
		zapLog.Error(fmt.Sprintf("Could not ping privilege service with err %v", err))
		return &privilegeClient, nil, err
	}
	return &privilegeClient, conn, err
}
