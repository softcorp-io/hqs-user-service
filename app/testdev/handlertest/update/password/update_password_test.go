package testing

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	handler "github.com/softcorp-io/hqs-user-service/handler"
	mock "github.com/softcorp-io/hqs-user-service/testdev/mock"
	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
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

func TestUpdatePassword(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	updatedPassword := "Updatedpassword1234"

	// act
	userResponse, err := myHandler.UpdatePassword(ctx, &proto.UpdatePasswordRequest{
		OldPassword: seedPassword,
		NewPassword: updatedPassword,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)
}

func TestUpdatePasswordIllegalPassowrd(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	updatedPassword := "updatedpassword"

	// act
	userResponse, err := myHandler.UpdatePassword(ctx, &proto.UpdatePasswordRequest{
		OldPassword: seedPassword,
		NewPassword: updatedPassword,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}

func TestUpdateIllegalToken(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": "Illegal Token"})
	ctx = metadata.NewIncomingContext(ctx, md)

	updatedPassword := "Updatedpassword1234"

	// act
	userResponse, err := myHandler.UpdatePassword(ctx, &proto.UpdatePasswordRequest{
		OldPassword: seedPassword,
		NewPassword: updatedPassword,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}
