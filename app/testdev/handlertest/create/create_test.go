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

func TestCreateAllowed(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	createName := "Test User"
	createEmail := "testuser@softcorp.io"
	createPhone := "+45 88 88 88 88"
	createPassword := "TestPassword1234asda"
	createAllowView := true
	createAllowCreate := true
	createAllowPermission := true
	createAllowDelete := true

	// act
	userResponse, err := myHandler.Create(ctx, &proto.User{
		Name:            createName,
		Email:           createEmail,
		Phone:           createPhone,
		Password:        createPassword,
		AllowView:       createAllowView,
		AllowCreate:     createAllowCreate,
		AllowPermission: createAllowPermission,
		AllowDelete:     createAllowDelete,
	})

	// assert that we can get the user with above information
	assert.Equal(t, nil, err)
	getUserResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: createEmail,
	})
	assert.Equal(t, nil, err)
	assert.NotEmpty(t, userResponse)
	assert.NotEmpty(t, getUserResponse)
	assert.Equal(t, getUserResponse.User.Name, createName)
	assert.Equal(t, getUserResponse.User.Email, createEmail)
	assert.NotEqual(t, getUserResponse.User.Password, createPassword)
	assert.NotEmpty(t, getUserResponse.User.Phone)
}

func TestCreateDuplicateEmail(t *testing.T) {
	// configure
	mock.TruncateUsers()

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

	createName := "Test User"
	createEmail := seedEmail
	createPhone := "+45 88 88 88 88"
	createPassword := "TestPassword1234asda"
	createAllowView := true
	createAllowCreate := true
	createAllowPermission := true
	createAllowDelete := true
	createAllowBlock := true
	createBlocked := false
	createGender := false

	// act
	userResponse, err := myHandler.Create(ctx, &proto.User{
		Name:            createName,
		Email:           createEmail,
		Phone:           createPhone,
		Password:        createPassword,
		AllowView:       createAllowView,
		AllowCreate:     createAllowCreate,
		AllowPermission: createAllowPermission,
		AllowDelete:     createAllowDelete,
		AllowBlock:      createAllowBlock,
		Blocked:         createBlocked,
		Gender:          createGender,
	})

	// assert that we can get the user with above information
	assert.Error(t, err)
	assert.Empty(t, userResponse)
}

func TestCreateNotAllowed(t *testing.T) {
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

	createName := "Test User"
	createEmail := "testuser@softcorp.io"
	createPhone := "+45 88 88 88 88"
	createPassword := "TestPassword1234asda"
	createAllowView := true
	createAllowCreate := false
	createAllowPermission := false
	createAllowDelete := true

	// act
	userResponse, err := myHandler.Create(ctx, &proto.User{
		Name:            createName,
		Email:           createEmail,
		Phone:           createPhone,
		Password:        createPassword,
		AllowView:       createAllowView,
		AllowCreate:     createAllowCreate,
		AllowPermission: createAllowPermission,
		AllowDelete:     createAllowDelete,
	})

	// assert that we cannot get
	assert.Error(t, err)
	getUserResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: createEmail,
	})
	assert.Error(t, err)
	assert.Empty(t, getUserResponse)
	assert.Empty(t, userResponse)
}

func TestCreateIllegalName(t *testing.T) {
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

	createName := ""
	createEmail := "testuser@softcorp.io"
	createPhone := "+45 88 88 88 88"
	createPassword := "TestPassword1234asda"
	createAllowView := true
	createAllowCreate := false
	createAllowPermission := true
	createAllowDelete := true
	createAllowBlock := true
	createBlocked := false
	createGender := false

	// act
	userResponse, err := myHandler.Create(ctx, &proto.User{
		Name:            createName,
		Email:           createEmail,
		Phone:           createPhone,
		Password:        createPassword,
		Gender:          createGender,
		AllowView:       createAllowView,
		AllowCreate:     createAllowCreate,
		AllowPermission: createAllowPermission,
		AllowDelete:     createAllowDelete,
		AllowBlock:      createAllowBlock,
		Blocked:         createBlocked,
	})

	// assert that we cannot get
	assert.Error(t, err)

	getUserResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: createEmail,
	})
	assert.Error(t, err)
	assert.Empty(t, getUserResponse)
	assert.Empty(t, userResponse)
}

func TestCreateIllegalEmail(t *testing.T) {
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

	createName := ""
	createEmail := "testusersoftcorp.io"
	createPassword := "TestPassword1234asda"
	createAllowView := true
	createAllowCreate := true
	createAllowPermission := true
	createAllowDelete := true
	createAllowBlock := true
	createBlocked := false
	createGender := false

	// act
	userResponse, err := myHandler.Create(ctx, &proto.User{
		Name:            createName,
		Email:           createEmail,
		Password:        createPassword,
		Gender:          createGender,
		AllowView:       createAllowView,
		AllowCreate:     createAllowCreate,
		AllowPermission: createAllowPermission,
		AllowDelete:     createAllowDelete,
		AllowBlock:      createAllowBlock,
		Blocked:         createBlocked,
	})

	// assert that we cannot get
	assert.Error(t, err)
	getUserResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: createEmail,
	})
	assert.Error(t, err)
	assert.Empty(t, getUserResponse)
	assert.Empty(t, userResponse)
}

func TestCreateIllegalPassword(t *testing.T) {
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

	createName := ""
	createEmail := "testusersoftcorp.io"
	createPassword := "1234asda"
	createAllowView := true
	createAllowCreate := true
	createAllowPermission := true
	createAllowDelete := true
	createAllowBlock := true
	createBlocked := false
	createGender := false

	// act
	userResponse, err := myHandler.Create(ctx, &proto.User{
		Name:            createName,
		Email:           createEmail,
		Password:        createPassword,
		Gender:          createGender,
		AllowView:       createAllowView,
		AllowCreate:     createAllowCreate,
		AllowPermission: createAllowPermission,
		AllowDelete:     createAllowDelete,
		AllowBlock:      createAllowBlock,
		Blocked:         createBlocked,
	})

	// assert that we cannot get
	assert.Error(t, err)
	getUserResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: createEmail,
	})
	assert.Error(t, err)
	assert.Empty(t, getUserResponse)
	assert.Empty(t, userResponse)
}

func TestCreateUserIllegalToken(t *testing.T) {
	ctx := context.Background()
	// build context with token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": "invalid token"})
	ctx = metadata.NewIncomingContext(ctx, md)

	createName := "Test User"
	createEmail := "testuser@softcorp.io"
	createPassword := "TestPassword1234asda"
	createAllowView := true
	createAllowCreate := true
	createAllowPermission := true
	createAllowDelete := true
	createAllowBlock := true
	createBlocked := false
	createGender := false

	// act
	userResponse, err := myHandler.Create(ctx, &proto.User{
		Name:            createName,
		Email:           createEmail,
		Password:        createPassword,
		Gender:          createGender,
		AllowView:       createAllowView,
		AllowCreate:     createAllowCreate,
		AllowPermission: createAllowPermission,
		AllowDelete:     createAllowDelete,
		AllowBlock:      createAllowBlock,
		Blocked:         createBlocked,
	})

	// assert that we cannot get
	assert.Error(t, err)
	getUserResponse, err := myHandler.GetByEmail(ctx, &proto.User{
		Email: createEmail,
	})
	assert.Error(t, err)
	assert.Empty(t, getUserResponse)
	assert.Empty(t, userResponse)
}
