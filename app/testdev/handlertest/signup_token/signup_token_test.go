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

func TestGenerateSignupToken(t *testing.T) {
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
	seedAllowReset := true
	seedBlocked := false
	seedGender := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedAllowReset, seedBlocked, seedGender)

	// arrange

	ctx := context.Background()

	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	singupToken, err := myHandler.GenerateSignupToken(ctx, &proto.Request{})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, singupToken)
	assert.NotEmpty(t, singupToken.Token)
}

func TestGenerateSignupTokenUnauthorized(t *testing.T) {
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := false
	seedAllowPermission := true
	seedAllowDelete := true
	seedAllowBlock := true
	seedAllowReset := true
	seedBlocked := false
	seedGender := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedAllowReset, seedBlocked, seedGender)

	// arrange

	ctx := context.Background()

	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	singupToken, err := myHandler.GenerateSignupToken(ctx, &proto.Request{})

	// assert
	assert.Error(t, err)
	assert.Empty(t, singupToken)
}

func TestSingupWithToken(t *testing.T) {
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
	seedAllowReset := true
	seedBlocked := false
	seedGender := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedAllowReset, seedBlocked, seedGender)

	ctx := context.Background()

	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	singupToken, err := myHandler.GenerateSignupToken(ctx, &proto.Request{})

	assert.Equal(t, nil, err)
	assert.NotEmpty(t, singupToken)

	// arrange

	// build context with token
	md = metadata.New(map[string]string{"token": singupToken.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	createUserName := "Token User"
	createUserEmail := "tokenuser@softcorp.io"
	createUserPassword := "RandomPassword1234"
	createUserPhone := "4423423123"

	// act
	userResponse, err := myHandler.Signup(ctx, &proto.User{
		Name:     createUserName,
		Email:    createUserEmail,
		Password: createUserPassword,
		Phone:    createUserPhone,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)
	assert.Equal(t, createUserName, userResponse.User.Name)
	assert.Equal(t, createUserEmail, userResponse.User.Email)
	assert.Equal(t, createUserPhone, userResponse.User.Phone)
	assert.NotEqual(t, createUserPassword, userResponse.User.Password)
}

func TestSingupWithSpecificPrivilege(t *testing.T) {
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
	seedAllowReset := true
	seedBlocked := false
	seedGender := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedAllowReset, seedBlocked, seedGender)

	ctx := context.Background()

	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	singupToken, err := myHandler.GenerateSignupToken(ctx, &proto.Request{})

	assert.Equal(t, nil, err)
	assert.NotEmpty(t, singupToken)

	// arrange

	// build context with token
	md = metadata.New(map[string]string{"token": singupToken.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	createUserName := "Token User"
	createUserEmail := "tokenuser@softcorp.io"
	createUserPassword := "RandomPassword1234"
	createUserPhone := "4423423123"

	// act
	userResponse, err := myHandler.Signup(ctx, &proto.User{
		Name:     createUserName,
		Email:    createUserEmail,
		Password: createUserPassword,
		Phone:    createUserPhone,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)
	assert.Equal(t, createUserName, userResponse.User.Name)
	assert.Equal(t, createUserEmail, userResponse.User.Email)
	assert.Equal(t, createUserPhone, userResponse.User.Phone)
	assert.Equal(t, "default", userResponse.User.PrivilegeID)
	assert.NotEqual(t, createUserPassword, userResponse.User.Password)
}

func TestCannotUseSignupTokenTwice(t *testing.T) {
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
	seedAllowReset := true
	seedBlocked := false
	seedGender := false
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete, seedAllowBlock, seedAllowReset, seedBlocked, seedGender)

	ctx := context.Background()

	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	singupToken, err := myHandler.GenerateSignupToken(ctx, &proto.Request{})

	assert.Equal(t, nil, err)
	assert.NotEmpty(t, singupToken)

	// arrange
	createUserOneName := "Token User 1"
	createUserOneEmail := "tokenuser1@softcorp.io"
	createUserOnePassword := "RandomPassword1234"
	createUserOnePhone := "34534123"

	createUserTwoName := "Token User 2"
	createUserTwoEmail := "tokenuser2@softcorp.io"
	createUserTwoPassword := "RandomPassword1234"
	createUserTwoPhone := "442342312343"

	// act
	md = metadata.New(map[string]string{"token": singupToken.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	_, _ = myHandler.Signup(ctx, &proto.User{
		Name:     createUserOneName,
		Email:    createUserOneEmail,
		Password: createUserOnePassword,
		Phone:    createUserOnePhone,
	})

	userResponse, err := myHandler.Signup(ctx, &proto.User{
		Name:     createUserTwoName,
		Email:    createUserTwoEmail,
		Password: createUserTwoPassword,
		Phone:    createUserTwoPhone,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}
