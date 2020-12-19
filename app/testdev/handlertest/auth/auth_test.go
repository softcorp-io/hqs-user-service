package testing

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
	handler "github.com/softcorp-io/hqs_user_service/handler"
	mock "github.com/softcorp-io/hqs_user_service/testdev/mock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
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

func TestAuth(t *testing.T) {
	// configure
	mock.TruncateUsers()
	log.Println("we get here")

	// arrange
	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedGender := false
	seedAllowView := true
	seedAllowCreate := true
	seedAllowPermission := true
	seedAllowDelete := true
	seedAllowBlock := true
	seedBlocked := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedBlocked, seedGender)

	// act
	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, tokenResponse)
}

func TestAuthUserBlocked(t *testing.T) {
	// configure
	mock.TruncateUsers()
	log.Println("we get here")

	// arrange
	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedGender := false
	seedAllowView := true
	seedAllowCreate := true
	seedAllowPermission := true
	seedAllowDelete := true
	seedAllowBlock := true
	seedBlocked := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedBlocked, seedGender)

	// act
	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, tokenResponse)
}

func TestAuthWrongPassword(t *testing.T) {
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

	// act
	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: "WrongPassword1234",
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, tokenResponse)
}

func TestAuthNoPassword(t *testing.T) {
	// configure
	mock.TruncateUsers()

	// arrange
	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	seedAllowBlock := true
	seedBlocked := false
	seedGender := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedBlocked, seedGender)

	// act
	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: "",
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, tokenResponse)
}

func TestGetAuthHistoryValidToken(t *testing.T) {
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
	tokenResponseOne, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, tokenResponseOne.Token)

	tokenResponseTwo, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, tokenResponseTwo.Token)

	// build context
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponseOne.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act

	authHistoryResponse, err := myHandler.GetAuthHistory(ctx, &proto.Request{})

	// assert
	assert.Nil(t, err)
	assert.NotEmpty(t, authHistoryResponse)
	assert.Equal(t, 2, len(authHistoryResponse.AuthHistory))
}

func TestGetAuthHistoryInvalidToken(t *testing.T) {
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
	_, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Nil(t, err)

	tokenResponseTwo, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, tokenResponseTwo.Token)

	// build context
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": "InvalidToken"})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act

	authHistoryResponse, err := myHandler.GetAuthHistory(ctx, &proto.Request{})

	// assert
	assert.Error(t, err)
	assert.Empty(t, authHistoryResponse)
}
