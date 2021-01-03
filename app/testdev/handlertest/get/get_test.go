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

func TestGet(t *testing.T) {
	// configure
	mock.TruncateUsers()

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
	id := mock.Seed(seedTwoName, seedTwoEmail, seedTwoPhone, seedTwoPassword, seedTwoAllowView, seedTwoAllowCreate, seedTwoAllowPermission, seedTwoAllowDelete, seedTwoAllowBlock, seedTwoBlocked, seedTwoGender)

	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedOneEmail,
		Password: seedOnePassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.Get(ctx, &proto.User{
		Id: id,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)
	assert.Equal(t, userResponse.User.Name, seedTwoName)
	assert.Equal(t, userResponse.User.Email, seedTwoEmail)
	assert.NotEqual(t, userResponse.User.Password, seedTwoPassword)
	assert.NotEmpty(t, userResponse.User.Image)
}

func TestGetIllegalToken(t *testing.T) {
	// configure
	mock.TruncateUsers()

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
	id := mock.Seed(seedTwoName, seedTwoEmail, seedTwoPhone, seedTwoPassword, seedTwoAllowView, seedTwoAllowCreate, seedTwoAllowPermission, seedTwoAllowDelete, seedTwoAllowBlock, seedTwoBlocked, seedTwoGender)

	ctx := context.Background()

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": "Illegal Token"})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.Get(ctx, &proto.User{
		Id: id,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}

func TestGetAll(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	seedThreeName := "Seed User 3"
	seedThreeEmail := "seeduser3@softcorp.io"
	seedThreePassword := "RandomPassword1234"
	seedThreePhone := "+45 88 88 88 88"
	seedThreeAllowView := true
	seedThreeAllowCreate := true
	seedThreeAllowPermission := true
	seedThreeAllowDelete := true
	seedThreeAllowBlock := true
	seedThreeBlocked := false
	seedThreeGender := false

	_ = mock.Seed(seedOneName, seedOneEmail, seedOnePhone, seedOnePassword, seedOneAllowView, seedOneAllowCreate, seedOneAllowPermission, seedOneAllowDelete, seedOneAllowBlock, seedOneBlocked, seedOneGender)
	_ = mock.Seed(seedTwoName, seedTwoEmail, seedTwoPhone, seedTwoPassword, seedTwoAllowView, seedTwoAllowCreate, seedTwoAllowPermission, seedTwoAllowDelete, seedTwoAllowBlock, seedTwoBlocked, seedTwoGender)
	_ = mock.Seed(seedThreeName, seedThreeEmail, seedThreePhone, seedThreePassword, seedThreeAllowView, seedThreeAllowCreate, seedThreeAllowPermission, seedThreeAllowDelete, seedThreeAllowBlock, seedThreeBlocked, seedThreeGender)

	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedOneEmail,
		Password: seedOnePassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.GetAll(ctx, &proto.Request{})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)
	assert.Equal(t, 3, len(userResponse.Users))
	for _, user := range userResponse.Users {
		assert.NotEmpty(t, user.Name)
		assert.NotEmpty(t, user.Id)
		assert.NotEmpty(t, user.Image)
		assert.NotEmpty(t, user.Email)
		assert.Empty(t, user.Password)
	}
}

func TestGetAllIllegalToken(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	seedThreeName := "Seed User 3"
	seedThreeEmail := "seeduser3@softcorp.io"
	seedThreePassword := "RandomPassword1234"
	seedThreePhone := "+45 88 88 88 88"
	seedThreeAllowView := true
	seedThreeAllowCreate := true
	seedThreeAllowPermission := true
	seedThreeAllowDelete := true
	seedThreeAllowBlock := true
	seedThreeBlocked := false
	seedThreeGender := false

	_ = mock.Seed(seedOneName, seedOneEmail, seedOnePhone, seedOnePassword, seedOneAllowView, seedOneAllowCreate, seedOneAllowPermission, seedOneAllowDelete, seedOneAllowBlock, seedOneBlocked, seedOneGender)
	_ = mock.Seed(seedTwoName, seedTwoEmail, seedTwoPhone, seedTwoPassword, seedTwoAllowView, seedTwoAllowCreate, seedTwoAllowPermission, seedTwoAllowDelete, seedTwoAllowBlock, seedTwoBlocked, seedTwoGender)
	_ = mock.Seed(seedThreeName, seedThreeEmail, seedThreePhone, seedThreePassword, seedThreeAllowView, seedThreeAllowCreate, seedThreeAllowPermission, seedThreeAllowDelete, seedThreeAllowBlock, seedThreeBlocked, seedThreeGender)

	// arrange
	ctx := context.Background()
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": "Illegal token"})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.GetAll(ctx, &proto.Request{})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}

func TestGetByEmail(t *testing.T) {
	// configure
	mock.TruncateUsers()

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
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedOneEmail,
		Password: seedOnePassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: seedTwoEmail,
	})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)
	assert.NotEmpty(t, userResponse.User.Image)
	assert.Equal(t, userResponse.User.Name, seedTwoName)
	assert.Equal(t, userResponse.User.Email, seedTwoEmail)
	assert.NotEqual(t, userResponse.User.Password, seedTwoPassword)
}

func TestGetByEmailIllegalToken(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": "Illegal Token"})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: seedTwoEmail,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}

func TestByValidAuthToken(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	_ = mock.Seed(seedOneName, seedOneEmail, seedOnePhone, seedOnePassword, seedOneAllowView, seedOneAllowCreate, seedOneAllowPermission, seedOneAllowDelete, seedOneAllowBlock, seedOneBlocked, seedOneGender)

	// arrange
	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedOneEmail,
		Password: seedOnePassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.GetByToken(ctx, &proto.Request{})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)
	assert.Equal(t, seedOneName, userResponse.User.Name)
	assert.NotEmpty(t, userResponse.User.Image)
	assert.NotEqual(t, seedOnePassword, userResponse.User.Password)
	assert.Equal(t, seedOneAllowView, userResponse.User.AllowView)
	assert.Equal(t, seedOneAllowCreate, userResponse.User.AllowCreate)
	assert.Equal(t, seedOneAllowPermission, userResponse.User.AllowPermission)
	assert.Equal(t, seedOneAllowDelete, userResponse.User.AllowDelete)
}

func TestGetNotAllowed(t *testing.T) {
	// configure
	mock.TruncateUsers()

	seedOneName := "Seed User 1"
	seedOneEmail := "seeduser1@softcorp.io"
	seedOnePassword := "RandomPassword1234"
	seedOnePhone := "+45 88 88 88 88"
	seedOneAllowView := false
	seedOneAllowCreate := false
	seedOneAllowPermission := false
	seedOneAllowDelete := false
	seedOneAllowBlock := false
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
	id := mock.Seed(seedTwoName, seedTwoEmail, seedTwoPhone, seedTwoPassword, seedTwoAllowView, seedTwoAllowCreate, seedTwoAllowPermission, seedTwoAllowDelete, seedTwoAllowBlock, seedTwoBlocked, seedTwoGender)

	ctx := context.Background()
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedOneEmail,
		Password: seedOnePassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.Get(ctx, &proto.User{
		Id: id,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}

func TestGetByEmailNotAllowed(t *testing.T) {
	// configure
	mock.TruncateUsers()

	seedOneName := "Seed User 1"
	seedOneEmail := "seeduser1@softcorp.io"
	seedOnePassword := "RandomPassword1234"
	seedOnePhone := "+45 88 88 88 88"
	seedOneAllowView := false
	seedOneAllowCreate := false
	seedOneAllowPermission := false
	seedOneAllowDelete := false
	seedOneAllowBlock := false
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
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedOneEmail,
		Password: seedOnePassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: seedTwoEmail,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}

func TestGetAllNotAllowed(t *testing.T) {
	// configure
	mock.TruncateUsers()

	seedOneName := "Seed User 1"
	seedOneEmail := "seeduser1@softcorp.io"
	seedOnePassword := "RandomPassword1234"
	seedOnePhone := "+45 88 88 88 88"
	seedOneAllowView := false
	seedOneAllowCreate := false
	seedOneAllowPermission := false
	seedOneAllowDelete := false
	seedOneAllowBlock := false
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
	tokenResponse, err := myHandler.Auth(ctx, &proto.User{
		Email:    seedOneEmail,
		Password: seedOnePassword,
	})

	assert.Equal(t, err, nil)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": tokenResponse.Token})
	ctx = metadata.NewIncomingContext(ctx, md)

	// act
	userResponse, err := myHandler.GetAll(ctx, &proto.Request{})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}
