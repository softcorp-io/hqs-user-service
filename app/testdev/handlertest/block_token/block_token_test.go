package testing

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
	handler "github.com/softcorp-io/hqs_user_service/handler"
	mock "github.com/softcorp-io/hqs_user_service/testdev/mock"
	"github.com/stretchr/testify/assert"
)

var myHandler *handler.Handler

func TestMain(m *testing.M) {
	handler, err := mock.NewHandler()
	if err != nil {
		mock.TearDownMongoDocker()
		log.Fatalf("Could not setup handler: %v", err)
	}

	myHandler = handler

	code := m.Run()

	mock.TearDownMongoDocker()
	os.Exit(code)
}

func TestBlockToken(t *testing.T) {
	// configure
	mock.TruncateUsers()

	// arrange
	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowPermission := true
	seedAllowDelete := true
	seedAllowBlock := true
	seedBlocked := false
	seedGender := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedBlocked, seedGender)

	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Equal(t, nil, err)
	assert.NotEmpty(t, tokenResponse)

	validateTokenResponse, err := myHandler.ValidateToken(ctx, &proto.Token{
		Token: tokenResponse.Token,
	})
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, validateTokenResponse)

	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	blockTokenResponse, err := myHandler.BlockToken(ctx, &proto.Token{
		Token: tokenResponse.Token,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.Equal(t, false, blockTokenResponse.Valid)

	// check that we cannot validate the token
	validateTokenResponse, err = myHandler.ValidateToken(ctx, &proto.Token{
		Token: tokenResponse.Token,
	})
	assert.Error(t, err)
	assert.Empty(t, validateTokenResponse)
}

func TestCannotBlockOtherUsers(t *testing.T) {
	// configure
	mock.TruncateUsers()

	// arrange
	seedOneName := "Seed User 1"
	seedOneEmail := "seeduser1@softcorp.io"
	seedOnePassword := "RandomPassword1234"
	seedOnePhone := "+45 88 88 88 88"
	seedOneAllowView := true
	seedOneAllowCreate := true
	seedOneAllowPermission := true
	seedOneAllowDelete := true
	seedOneAllowBlock := true
	seedOneBlocked := false
	seedOneGender := false

	seedTwoName := "Seed User 2"
	seedTwoEmail := "seeduser2@softcorp.io"
	seedTwoPassword := "RandomPassword1234"
	seedTwoPhone := "+45 88 88 88 88"
	seedTwoAllowView := true
	seedTwoAllowCreate := true
	seedTwoAllowPermission := true
	seedTwoAllowDelete := true
	seedTwoAllowBlock := true
	seedTwoBlocked := false
	seedTwoGender := false

	_ = mock.Seed(seedOneName, seedOneEmail, seedOnePhone, seedOnePassword, seedOneAllowView, seedOneAllowCreate, seedOneAllowPermission, seedOneAllowDelete, seedOneAllowBlock, seedOneBlocked, seedOneGender)
	_ = mock.Seed(seedTwoName, seedTwoEmail, seedTwoPhone, seedTwoPassword, seedTwoAllowView, seedTwoAllowCreate, seedTwoAllowPermission, seedTwoAllowDelete, seedTwoAllowBlock, seedTwoBlocked, seedTwoGender)

	ctx := context.Background()
	tokenResponseOne, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedOneEmail,
		Password: seedOnePassword,
	})

	tokenResponseTwo, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedTwoEmail,
		Password: seedTwoPassword,
	})

	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponseOne.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	_, err = myHandler.BlockToken(ctx, &proto.Token{
		Token: tokenResponseTwo.Token,
	})

	// assert
	assert.Error(t, err)

	// check that we CANO validate the token
	validateTokenResponse, err := myHandler.ValidateToken(ctx, &proto.Token{
		Token: tokenResponseTwo.Token,
	})
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, validateTokenResponse)
}

func TestBlockByID(t *testing.T) {
	// configure
	mock.TruncateUsers()

	// arrange
	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowPermission := true
	seedAllowDelete := true
	seedAllowBlock := true
	seedBlocked := false
	seedGender := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedBlocked, seedGender)

	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Equal(t, nil, err)

	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	authHistoryResponse, err := myHandler.GetAuthHistory(ctx, &proto.Request{})
	assert.Equal(t, nil, err)

	// act
	_, err = myHandler.BlockTokenByID(ctx, &proto.BlockTokenRequest{
		TokenID: authHistoryResponse.AuthHistory[0].TokenID,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.Equal(t, false, tokenResponse.Valid)

	// check that we cannot validate the token
	validateTokenResponse, err := myHandler.ValidateToken(ctx, &proto.Token{
		Token: tokenResponse.Token,
	})
	assert.Error(t, err)
	assert.Empty(t, validateTokenResponse)
}
