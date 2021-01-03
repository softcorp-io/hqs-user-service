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

func TestUpdateProfile(t *testing.T) {
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
	id := mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedBlocked, seedGender)

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

	updatedName := "Updated User"
	updatedEmail := "updateduser@softcorp.io"
	updatedPhone := "902841023912349"
	updatedGender := true

	// act
	userResponse, err := myHandler.UpdateProfile(ctx, &proto.User{
		Name:   updatedName,
		Email:  updatedEmail,
		Phone:  updatedPhone,
		Gender: updatedGender,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)

	// check profile is updated
	userResponse, err = myHandler.Get(ctx, &proto.User{
		Id: id,
	})

	assert.Equal(t, nil, err)
	assert.Equal(t, updatedName, userResponse.User.Name)
	assert.Equal(t, updatedEmail, userResponse.User.Email)
	assert.Equal(t, updatedPhone, userResponse.User.Phone)
	assert.Equal(t, updatedGender, userResponse.User.Gender)
}

func TestUpdateProfileWrongEmail(t *testing.T) {
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
	id := mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedBlocked, seedGender)

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

	updatedName := "Updated User"
	updatedEmail := "updateduser-softcorp.io"
	updatedPhone := "920312312423"
	updatedGender := true

	// act
	userResponse, err := myHandler.UpdateProfile(ctx, &proto.User{
		Name:   updatedName,
		Email:  updatedEmail,
		Phone:  updatedPhone,
		Gender: updatedGender,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)

	// check profile is NOT updated
	userResponse, err = myHandler.Get(ctx, &proto.User{
		Id: id,
	})

	assert.Equal(t, nil, err)
	assert.Equal(t, seedName, userResponse.User.Name)
	assert.Equal(t, seedEmail, userResponse.User.Email)
	assert.Equal(t, seedPhone, userResponse.User.Phone)
	assert.Equal(t, seedGender, userResponse.User.Gender)
}

func TestUpdateProfileWrongName(t *testing.T) {
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
	id := mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedBlocked, seedGender)

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

	updatedName := ""
	updatedEmail := "updateduser@softcorp.io"

	// act
	userResponse, err := myHandler.UpdateProfile(ctx, &proto.User{
		Name:  updatedName,
		Email: updatedEmail,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)

	// check profile is NOT updated
	userResponse, err = myHandler.Get(ctx, &proto.User{
		Id: id,
	})

	assert.Equal(t, nil, err)
	assert.Equal(t, seedName, userResponse.User.Name)
	assert.Equal(t, seedEmail, userResponse.User.Email)
	assert.Equal(t, seedPhone, userResponse.User.Phone)
}

func TestUpdateProfileIllegalToken(t *testing.T) {
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

	updatedName := "Updated User"
	updatedEmail := "updateduser@softcorp.io"

	// act
	userResponse, err := myHandler.UpdateProfile(ctx, &proto.User{
		Name:  updatedName,
		Email: updatedEmail,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}
