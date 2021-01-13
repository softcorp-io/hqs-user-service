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

func TestUpdatePrivilegesAllowed(t *testing.T) {
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
	seedOneAllowReset := true
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
	seedTwoAllowReset := true
	seedTwoBlocked := false
	seedTwoGender := false

	_ = mock.Seed(seedOneName, seedOneEmail, seedOnePhone, seedOnePassword, seedOneAllowView, seedOneAllowCreate, seedOneAllowPermission, seedOneAllowDelete, seedOneAllowBlock, seedOneAllowReset, seedOneBlocked, seedOneGender)
	id2 := mock.Seed(seedTwoName, seedTwoEmail, seedTwoPhone, seedTwoPassword, seedTwoAllowView, seedTwoAllowCreate, seedTwoAllowPermission, seedTwoAllowDelete, seedTwoAllowBlock, seedTwoAllowReset, seedTwoBlocked, seedTwoGender)

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
	newPrivID := "new id"
	userResponse, err := myHandler.UpdatePrivileges(ctx, &proto.User{Id: id2, PrivilegeID: newPrivID})

	// assert
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)

	// check permissions are updated
	userResponse, err = myHandler.Get(ctx, &proto.User{
		Id: id2,
	})
	assert.Equal(t, userResponse.User.PrivilegeID, newPrivID)
	assert.Equal(t, nil, err)
}

func TestUpdateAllowanceNotAllowed(t *testing.T) {
	// configure
	mock.TruncateUsers()

	seedOneName := "Seed User 1"
	seedOneEmail := "seeduser1@softcorp.io"
	seedOnePassword := "RandomPassword1234"
	seedOnePhone := "+45 88 88 88 88"
	seedOneAllowView := true
	seedOneAllowCreate := true
	seedOneAllowPermission := false
	seedOneAllowDelete := true
	seedOneAllowBlock := true
	seedOneAllowReset := true
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
	seedTwoAllowReset := true
	seedTwoBlocked := false
	seedTwoGender := false

	_ = mock.Seed(seedOneName, seedOneEmail, seedOnePhone, seedOnePassword, seedOneAllowView, seedOneAllowCreate, seedOneAllowPermission, seedOneAllowDelete, seedOneAllowBlock, seedOneAllowReset, seedOneBlocked, seedOneGender)
	id2 := mock.Seed(seedTwoName, seedTwoEmail, seedTwoPhone, seedTwoPassword, seedTwoAllowView, seedTwoAllowCreate, seedTwoAllowPermission, seedTwoAllowDelete, seedTwoAllowBlock, seedTwoAllowReset, seedTwoBlocked, seedTwoGender)

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
	newPrivID := "new id"
	userResponse, err := myHandler.UpdatePrivileges(ctx, &proto.User{
		Id:          id2,
		PrivilegeID: newPrivID,
	})

	// assert
	assert.Error(t, err)
	assert.Empty(t, userResponse)

	// check permissions are NOT updated
	userResponse, err = myHandler.Get(ctx, &proto.User{
		Id: id2,
	})

	assert.Equal(t, nil, err)
	assert.NotEqual(t, userResponse.User.PrivilegeID, newPrivID)
}
