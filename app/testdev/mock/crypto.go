package mock

import (
	"os"

	crypto "github.com/softcorp-io/hqs-user-service/crypto"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// GetCrypto - returns a service, connected to a docker container.
func GetCrypto() (*crypto.TokenService, *mongo.Collection, *mongo.Collection, error) {
	err := SetupDockerMongo()
	if err != nil {
		_ = TearDownMongoDocker()
		return nil, nil, nil, err
	}

	os.Setenv("USER_CRYPTO_JWT_KEY", "someverysecurekey")
	os.Setenv("RESET_PASSWORD_CRYPTO_JWT_KEY", "someverysecurekey")
	os.Setenv("AUTH_HISTORY_TTL", "5s")
	os.Setenv("USER_TOKEN_TTL", "5s")
	os.Setenv("SIGNUP_TOKEN_TTL", "5s")
	os.Setenv("RESET_PASS_TTL", "5s")
	os.Setenv("EMAIL_SIGNUP_LINK_BASE", "https://hqs.softcorp.io/signup/")

	zapLog, _ := zap.NewProduction()

	tokenService, err := crypto.NewTokenService(mongoAuthCollection, mongoTokenCollection, zapLog)
	if err != nil {
		return nil, nil, nil, err
	}

	return tokenService, mongoAuthCollection, mongoTokenCollection, nil
}
