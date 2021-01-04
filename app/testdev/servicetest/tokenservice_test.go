package testing

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"google.golang.org/grpc/metadata"

	service "github.com/softcorp-io/hqs-user-service/service"
	mock "github.com/softcorp-io/hqs-user-service/testdev/mock"
	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
)

var myService *service.TokenService
var mongoAuthCollection *mongo.Collection
var mongoTokenCollection *mongo.Collection

func TestMain(m *testing.M) {
	service, tempMongoAuthCollection, tempMongoTokenCollection, err := mock.GetService()
	if err != nil {
		mock.TearDownMongoDocker()
		log.Fatalf("Could not setup handler: %v", err)
	}
	mongoAuthCollection = tempMongoAuthCollection
	mongoTokenCollection = tempMongoTokenCollection
	myService = service

	code := m.Run()

	mock.TearDownMongoDocker()

	os.Exit(code)
}

func TestEncoderDecoder(t *testing.T) {
	// arrange
	name := "Test User"
	email := "testuser@softcorp.io"
	password := "Tester1235123"

	// act
	token, errEncode := myService.Encode(context.Background(), &proto.User{
		Name:     name,
		Email:    email,
		Password: password,
	}, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())

	claims, errDecode := myService.Decode(context.Background(), token, myService.GetUserCryptoKey())

	// assert
	// encoder
	assert.Equal(t, nil, errEncode)
	assert.NotEmpty(t, token)
	// decoder
	assert.Equal(t, nil, errDecode)
	assert.NotEmpty(t, claims)
	assert.Equal(t, name, claims.User.Name)
	assert.Equal(t, email, claims.User.Email)
	assert.Equal(t, password, claims.User.Password)
}

func TestEncoderDecoderTokenExpiration(t *testing.T) {
	// arrange
	name := "Test User"
	email := "testuser@softcorp.io"
	password := "Tester1235123"

	// act
	token, errEncode := myService.Encode(context.Background(), &proto.User{
		Name:     name,
		Email:    email,
		Password: password,
	}, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	time.Sleep(time.Second * 6)
	claims, errDecode := myService.Decode(context.Background(), token, myService.GetUserCryptoKey())

	// assert
	// encoder
	assert.Equal(t, nil, errEncode)
	assert.NotEmpty(t, token)
	// decoder
	assert.Error(t, errDecode)
	assert.Empty(t, claims)
}

func TestBlockToken(t *testing.T) {
	// configure
	name := "Test User 23"
	email := "testuser@softcorp.io"
	password := "Tester1235123"

	// arrange
	token, errEncode := myService.Encode(context.Background(), &proto.User{
		Name:     name,
		Email:    email,
		Password: password,
	}, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())

	claims, errDecode := myService.Decode(context.Background(), token, myService.GetUserCryptoKey())
	assert.Equal(t, nil, errEncode)
	assert.NotEmpty(t, token)
	assert.Equal(t, nil, errDecode)
	assert.NotEmpty(t, claims)
	assert.Equal(t, name, claims.User.Name)
	assert.Equal(t, email, claims.User.Email)
	assert.Equal(t, password, claims.User.Password)

	// act
	err := myService.BlockToken(context.Background(), claims.ID)

	// assert
	assert.Equal(t, nil, err)
	claims, err = myService.Decode(context.Background(), token, myService.GetUserCryptoKey())
	assert.Error(t, err)
	assert.Empty(t, claims)
}

func TestBlockAllTokens(t *testing.T) {
	// configure
	name := "Test User 23"
	email := "testuser@softcorp.io"
	password := "Tester1235123"
	id := "veryUniqueID1234"

	user := proto.User{
		Name:     name,
		Email:    email,
		Password: password,
		Id:       id,
	}

	// arrange
	tokenOne, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	tokenTwo, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	// act 1
	err = myService.AddAuthToHistory(context.Background(), &user, tokenOne, true)
	assert.Equal(t, nil, err)
	tokenHistory, err := myService.GetAuthHistory(context.Background(), &user)

	// assert 1
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(tokenHistory))
	claimsOne, err := myService.Decode(context.Background(), tokenOne, myService.GetUserCryptoKey())
	assert.Equal(t, nil, err)
	assert.Equal(t, tokenHistory[0].TokenID, claimsOne.ID)

	// act 2
	err = myService.AddAuthToHistory(context.Background(), &user, tokenTwo, true)
	assert.Equal(t, nil, err)
	tokenHistory, err = myService.GetAuthHistory(context.Background(), &user)

	// assert 2
	assert.Equal(t, nil, err)
	assert.Equal(t, 2, len(tokenHistory))
	claimsTwo, err := myService.Decode(context.Background(), tokenTwo, myService.GetUserCryptoKey())
	assert.Equal(t, nil, err)
	assert.Equal(t, tokenHistory[0].TokenID, claimsOne.ID)
	assert.Equal(t, tokenHistory[1].TokenID, claimsTwo.ID)

	// act 3
	err = myService.BlockAllUserToken(context.Background(), user.Id)
	tokenHistory, err = myService.GetAuthHistory(context.Background(), &user)
	claimsOne, tokenOneErr := myService.Decode(context.Background(), tokenOne, myService.GetUserCryptoKey())
	claimsTwo, tokenTwoErr := myService.Decode(context.Background(), tokenOne, myService.GetUserCryptoKey())

	// assert 3
	assert.Equal(t, 2, len(tokenHistory))
	assert.Error(t, tokenOneErr)
	assert.Error(t, tokenTwoErr)
	for _, auth := range tokenHistory {
		assert.False(t, auth.Valid)
	}
	// clean up
	err = myService.DeleteUserAuthHistory(context.Background(), &user)
	assert.Nil(t, err)
}

func TestGetAuthHistory(t *testing.T) {
	// configure
	name := "Test User 23"
	email := "testuser@softcorp.io"
	password := "Tester1235123"
	id := "veryUniqueID1234"

	user := proto.User{
		Name:     name,
		Email:    email,
		Password: password,
		Id:       id,
	}

	// arrange
	tokenOne, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	tokenTwo, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	// act 1
	err = myService.AddAuthToHistory(context.Background(), &user, tokenOne, true)
	assert.Equal(t, nil, err)
	tokenHistory, err := myService.GetAuthHistory(context.Background(), &user)

	// assert 1
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(tokenHistory))
	claimsOne, err := myService.Decode(context.Background(), tokenOne, myService.GetUserCryptoKey())
	assert.Equal(t, nil, err)
	assert.Equal(t, tokenHistory[0].TokenID, claimsOne.ID)

	// act 2
	err = myService.AddAuthToHistory(context.Background(), &user, tokenTwo, true)
	assert.Equal(t, nil, err)
	tokenHistory, err = myService.GetAuthHistory(context.Background(), &user)

	// assert 2
	assert.Equal(t, nil, err)
	assert.Equal(t, 2, len(tokenHistory))
	claimsTwo, err := myService.Decode(context.Background(), tokenTwo, myService.GetUserCryptoKey())
	assert.Equal(t, nil, err)
	assert.Equal(t, tokenHistory[0].TokenID, claimsOne.ID)
	assert.Equal(t, tokenHistory[1].TokenID, claimsTwo.ID)

	// clean up
	err = myService.DeleteUserAuthHistory(context.Background(), &user)
	assert.Nil(t, err)
}

func TestGetAuthHistoryExpiration(t *testing.T) {
	// configure
	name := "Test User 23"
	email := "testuser@softcorp.io"
	password := "Tester1235123"
	id := "veryUniqueID1234"

	user := proto.User{
		Name:     name,
		Email:    email,
		Password: password,
		Id:       id,
	}

	// arrange
	tokenOne, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	tokenTwo, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	// act 1
	err = myService.AddAuthToHistory(context.Background(), &user, tokenOne, true)
	assert.Equal(t, nil, err)
	tokenHistory, err := myService.GetAuthHistory(context.Background(), &user)

	// assert 1
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(tokenHistory))
	claimsOne, err := myService.Decode(context.Background(), tokenOne, myService.GetUserCryptoKey())
	assert.Nil(t, err)
	assert.Equal(t, tokenHistory[0].TokenID, claimsOne.ID)

	// act 2
	err = myService.AddAuthToHistory(context.Background(), &user, tokenTwo, true)
	assert.Equal(t, nil, err)
	tokenHistory, err = myService.GetAuthHistory(context.Background(), &user)

	// assert 2
	assert.Equal(t, nil, err)
	assert.Equal(t, 2, len(tokenHistory))
	claimsTwo, err := myService.Decode(context.Background(), tokenTwo, myService.GetUserCryptoKey())
	assert.Equal(t, nil, err)
	assert.Equal(t, tokenHistory[0].TokenID, claimsOne.ID)
	assert.Equal(t, tokenHistory[1].TokenID, claimsTwo.ID)

	// act 3
	time.Sleep(time.Second * 6)
	tokenHistory, err = myService.GetAuthHistory(context.Background(), &user)

	// assert 3
	assert.Nil(t, err)
	assert.Equal(t, 0, len(tokenHistory))
	claimsThree, err := myService.Decode(context.Background(), tokenTwo, myService.GetUserCryptoKey())
	assert.Error(t, err)
	assert.Empty(t, claimsThree)
	claimsThree, err = myService.Decode(context.Background(), tokenOne, myService.GetUserCryptoKey())
	assert.Error(t, err)
	assert.Empty(t, claimsThree)

	// clean up
	err = myService.DeleteUserAuthHistory(context.Background(), &user)
	assert.Nil(t, err)
}

func TestAuthIndex(t *testing.T) {
	// configure
	name := "Test User 23"
	email := "testuser@softcorp.io"
	password := "Tester1235123"
	id := "veryUniqueID1234"

	user := proto.User{
		Name:     name,
		Email:    email,
		Password: password,
		Id:       id,
	}

	// arrange
	tokenOne, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	tokenTwo, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	// act
	err = myService.AddAuthToHistory(context.Background(), &user, tokenOne, true)
	assert.Equal(t, nil, err)
	err = myService.AddAuthToHistory(context.Background(), &user, tokenTwo, true)
	assert.Equal(t, nil, err)
	tokenHistory, err := myService.GetAuthHistory(context.Background(), &user)
	assert.Equal(t, 2, len(tokenHistory))
	assert.Nil(t, err)

	// assert
	time.Sleep(time.Second * 75)
	cursor, err := mongoAuthCollection.Find(context.TODO(), bson.M{})
	assert.Nil(t, err)
	assert.Equal(t, 0, cursor.RemainingBatchLength())
}

func TestTokenIndex(t *testing.T) {
	// configure
	name := "Test User 23"
	email := "testuser@softcorp.io"
	password := "Tester1235123"
	id := "veryUniqueID1234"

	user := proto.User{
		Name:     name,
		Email:    email,
		Password: password,
		Id:       id,
	}

	// configure
	_, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	_, err = myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	cursor, err := mongoTokenCollection.Find(context.TODO(), bson.M{})
	assert.Nil(t, err)
	assert.Equal(t, 2, cursor.RemainingBatchLength())

	// assert
	time.Sleep(time.Second * 75)
	cursor, err = mongoTokenCollection.Find(context.TODO(), bson.M{})
	assert.Nil(t, err)
	assert.Equal(t, 0, cursor.RemainingBatchLength())
}

func TestSetLatitudeLongitude(t *testing.T) {
	// configure
	name := "Test User 23"
	email := "testuser@softcorp.io"
	password := "Tester1235123"
	id := "veryUniqueID1234"

	user := proto.User{
		Name:     name,
		Email:    email,
		Password: password,
		Id:       id,
	}

	// arrange
	tokenOne, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	tokenTwo, err := myService.Encode(context.Background(), &user, myService.GetUserCryptoKey(), myService.GetUserTokenTTL())
	assert.Equal(t, nil, err)

	// act 1
	// setup context
	latitude := "1.234"
	longitude := "1.234"
	md := metadata.New(map[string]string{"latitude": latitude, "longitude": longitude})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err = myService.AddAuthToHistory(ctx, &user, tokenOne, true)
	assert.Equal(t, nil, err)
	tokenHistory, err := myService.GetAuthHistory(context.Background(), &user)

	// assert 1
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(tokenHistory))
	claimsOne, err := myService.Decode(context.Background(), tokenOne, myService.GetUserCryptoKey())
	assert.Equal(t, nil, err)
	assert.Equal(t, tokenHistory[0].TokenID, claimsOne.ID)
	assert.Equal(t, tokenHistory[0].Latitude, 1.234)
	assert.Equal(t, tokenHistory[0].Longitude, 1.234)

	// act 2
	err = myService.AddAuthToHistory(context.Background(), &user, tokenTwo, true)
	assert.Equal(t, nil, err)
	tokenHistory, err = myService.GetAuthHistory(context.Background(), &user)

	// assert 2
	assert.Equal(t, nil, err)
	assert.Equal(t, 2, len(tokenHistory))
	claimsTwo, err := myService.Decode(context.Background(), tokenTwo, myService.GetUserCryptoKey())
	assert.Equal(t, nil, err)
	assert.Equal(t, tokenHistory[0].TokenID, claimsOne.ID)
	assert.Equal(t, tokenHistory[1].TokenID, claimsTwo.ID)
	assert.Equal(t, tokenHistory[1].Latitude, 0.0)
	assert.Equal(t, tokenHistory[1].Longitude, 0.0)

	// clean up
	err = myService.DeleteUserAuthHistory(context.Background(), &user)
	assert.Nil(t, err)
}
