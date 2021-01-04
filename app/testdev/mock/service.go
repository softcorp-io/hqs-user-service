package mock

import (
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	service "github.com/softcorp-io/hqs-user-service/service"
)

// GetService - returns a service, connected to a docker container.
func GetService() (*service.TokenService, *mongo.Collection, *mongo.Collection, error) {
	err := SetupDockerPostgres()
	if err != nil {
		_ = TearDownMongoDocker()
		return nil, nil, nil, err
	}

	os.Setenv("USER_CRYPTO_JWT_KEY", "someverysecurekey")
	os.Setenv("RESET_PASSWORD_CRYPTO_JWT_KEY", "someverysecurekey")
	os.Setenv("AUTH_HISTORY_TTL", "20s")
	os.Setenv("USER_TOKEN_TTL", "20s")
	os.Setenv("SIGNUP_TOKEN_TTL", "20s")
	os.Setenv("RESET_PASS_TTL", "20s")

	zapLog, _ := zap.NewProduction()

	tokenService, err := service.NewTokenService(mongoAuthCollection, mongoTokenCollection, zapLog)
	if err != nil {
		return nil, nil, nil, err
	}

	return tokenService, mongoAuthCollection, mongoTokenCollection, nil
}
