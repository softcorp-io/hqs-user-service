package mock

import (
	"bytes"
	"context"
	"os"
	"time"

	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"

	service "github.com/softcorp-io/hqs-user-service/crypto"
	handler "github.com/softcorp-io/hqs-user-service/handler"
	repository "github.com/softcorp-io/hqs-user-service/repository"
	emailProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_email_service"
	privilegeProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_privilege_service"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

// email client mock
type emailClientMock struct {
	mock.Mock
}

func (ec *emailClientMock) SendResetPasswordEmail(ctx context.Context, email *emailProto.ResetPasswordEmail, options ...grpc.CallOption) (*emailProto.Response, error) {
	return nil, nil
}

func (ec *emailClientMock) Ping(ctx context.Context, email *emailProto.Request, options ...grpc.CallOption) (*emailProto.Response, error) {
	return nil, nil
}

// storage client mock
type storageMock struct {
	mock.Mock
}

func (m *storageMock) Upload(data bytes.Buffer, filepath string, allowedTypes ...string) error {
	return nil
}

func (m *storageMock) Get(path string, duration time.Duration) (string, error) {
	return "some image", nil
}

func (m *storageMock) Delete(path string) error {
	return nil
}

// privilege client mock
type privilegeClientMock struct {
	privileges map[string]*privilegeProto.Privilege
}

var pcMock *privilegeClientMock

func (pc *privilegeClientMock) Ping(ctx context.Context, req *privilegeProto.Request, options ...grpc.CallOption) (*privilegeProto.Response, error) {
	return nil, nil
}

func (pc *privilegeClientMock) Create(ctx context.Context, req *privilegeProto.Privilege, options ...grpc.CallOption) (*privilegeProto.Response, error) {
	pc.privileges[req.Id] = req
	response := &privilegeProto.Response{}
	response.Privilege = req
	return response, nil
}

func (pc *privilegeClientMock) Update(ctx context.Context, req *privilegeProto.Privilege, options ...grpc.CallOption) (*privilegeProto.Response, error) {
	return &privilegeProto.Response{}, nil
}

func (pc *privilegeClientMock) Get(ctx context.Context, req *privilegeProto.Privilege, options ...grpc.CallOption) (*privilegeProto.Response, error) {
	response := &privilegeProto.Response{}
	response.Privilege = pc.privileges[req.Id]

	return response, nil
}

func (pc *privilegeClientMock) GetDefault(ctx context.Context, req *privilegeProto.Request, options ...grpc.CallOption) (*privilegeProto.Response, error) {
	response := &privilegeProto.Response{}
	response.Privilege = &privilegeProto.Privilege{
		Id:                     uuid.NewV4().String(),
		Name:                   "Default",
		ViewAllUsers:           false,
		CreateUser:             false,
		ManagePrivileges:       false,
		DeleteUser:             false,
		BlockUser:              false,
		SendResetPasswordEmail: false,
	}
	return response, nil
}

func (pc *privilegeClientMock) GetRoot(ctx context.Context, req *privilegeProto.Request, options ...grpc.CallOption) (*privilegeProto.Response, error) {
	response := &privilegeProto.Response{}
	response.Privilege = &privilegeProto.Privilege{
		Id:                     uuid.NewV4().String(),
		Name:                   "Root",
		ViewAllUsers:           true,
		CreateUser:             true,
		ManagePrivileges:       true,
		DeleteUser:             true,
		BlockUser:              true,
		SendResetPasswordEmail: true,
	}
	return response, nil
}

func (pc *privilegeClientMock) GetAll(ctx context.Context, req *privilegeProto.Request, options ...grpc.CallOption) (*privilegeProto.Response, error) {
	return nil, nil
}

func (pc *privilegeClientMock) Delete(ctx context.Context, req *privilegeProto.Privilege, options ...grpc.CallOption) (*privilegeProto.Response, error) {
	return nil, nil
}

// NewHandler - Returns a new handler & uses docker conainer for postgres database.
func NewHandler() (*handler.Handler, error) {
	err := SetupDockerMongo()
	if err != nil {
		_ = TearDownMongoDocker()
		return nil, err
	}

	// setup storage mock
	storageMock := new(storageMock)
	storageMock.On("Upload", mock.Anything).Return(nil)
	storageMock.On("Get", mock.Anything).Return("some image", nil)
	storageMock.On("Delete", mock.Anything).Return(nil)

	emailClientMock := new(emailClientMock)
	emailClientMock.On("SendResetPasswordEmail", mock.Anything).Return(nil, nil)
	emailClientMock.On("Ping", mock.Anything).Return(nil, nil)

	pcMock = &privilegeClientMock{
		privileges: map[string]*privilegeProto.Privilege{},
	}
	os.Setenv("USER_CRYPTO_JWT_KEY", "someverysecurekey")
	os.Setenv("RESET_PASSWORD_CRYPTO_JWT_KEY", "someverysecurekey")
	os.Setenv("AUTH_HISTORY_TTL", "20s")
	os.Setenv("USER_TOKEN_TTL", "20s")
	os.Setenv("SIGNUP_TOKEN_TTL", "20s")
	os.Setenv("RESET_PASS_TTL", "20s")
	os.Setenv("EMAIL_SIGNUP_LINK_BASE", "https://hqs.softcorp.io/signup/")

	zapLog, _ := zap.NewProduction()

	repo := repository.NewRepository(mongoUserCollection)
	tokenService, err := service.NewTokenService(mongoAuthCollection, mongoTokenCollection, zapLog)
	if err != nil {
		return nil, err
	}

	resultHandler := handler.NewHandler(repo, storageMock, tokenService, emailClientMock, pcMock, zapLog)

	return resultHandler, nil
}
