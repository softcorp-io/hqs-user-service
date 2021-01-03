package mock

import (
	"bytes"
	"os"
	"time"

	"go.uber.org/zap"

	handler "github.com/softcorp-io/hqs-user-service/handler"
	repository "github.com/softcorp-io/hqs-user-service/repository"
	service "github.com/softcorp-io/hqs-user-service/service"
	"github.com/stretchr/testify/mock"
)

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

// NewHandler - Returns a new handler & uses docker conainer for postgres database.
func NewHandler() (*handler.Handler, error) {
	err := SetupDockerPostgres()
	if err != nil {
		_ = TearDownMongoDocker()
		return nil, err
	}

	// setup storage mock
	storageMock := new(storageMock)
	storageMock.On("Upload", mock.Anything).Return(nil)
	storageMock.On("Get", mock.Anything).Return("some image", nil)
	storageMock.On("Delete", mock.Anything).Return(nil)

	os.Setenv("CRYPTO_JWT_KEY", "someverysecurekey")
	os.Setenv("AUTH_HISTORY_TTL", "20s")
	os.Setenv("TOKEN_TTL", "20s")
	os.Setenv("RESET_PASS_TTL", "20s")

	zapLog, _ := zap.NewProduction()

	repo := repository.NewRepository(mongoUserCollection)
	tokenService, err := service.NewTokenService(mongoAuthCollection, mongoTokenCollection, zapLog)
	if err != nil {
		return nil, err
	}

	resultHandler := handler.NewHandler(repo, storageMock, tokenService, zapLog)

	return resultHandler, nil
}
