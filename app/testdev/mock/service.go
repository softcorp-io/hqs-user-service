package mock

import (
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	service "github.com/softcorp-io/hqs_user_service/service"
)

// GetService - returns a service, connected to a docker container.
func GetService() (*service.TokenService, *mongo.Collection, *mongo.Collection, error) {
	err := SetupDockerPostgres()
	if err != nil {
		_ = TearDownMongoDocker()
		return nil, nil, nil, err
	}

	os.Setenv("CRYPTO_JWT_KEY", "A very secure key")
	os.Setenv("AUTH_HISTORY_TTL", "5s")
	os.Setenv("TOKEN_TTL", "5s")

	zapLog, _ := zap.NewProduction()

	tokenService, err := service.NewTokenService(mongoAuthCollection, mongoTokenCollection, zapLog)
	if err != nil {
		return nil, nil, nil, err
	}

	return tokenService, mongoAuthCollection, mongoTokenCollection, nil
}
