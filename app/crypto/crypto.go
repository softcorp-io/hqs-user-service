package crypto

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/metadata"

	uuid "github.com/satori/go.uuid"
	userProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// UserCryptoKey - key used for all authentication
var UserCryptoKey []byte

// GetUserCryptoKey - exports the UserCryptoKey
func (srv *TokenService) GetUserCryptoKey() []byte {
	return UserCryptoKey
}

// ResetPasswordCryptoKey - key used to create reset password token
var ResetPasswordCryptoKey []byte

// GetResetPasswordCryptoKey - exports the ResetPasswordCryptoKey
func (srv *TokenService) GetResetPasswordCryptoKey() []byte {
	return ResetPasswordCryptoKey
}

var authHistoryTTL time.Duration

// GetAuthHistoryTTL - returns ttl of token
func (srv *TokenService) GetAuthHistoryTTL() time.Duration {
	return authHistoryTTL
}

var userTokenTTL time.Duration

// GetUserTokenTTL - returns ttl of token
func (srv *TokenService) GetUserTokenTTL() time.Duration {
	return userTokenTTL
}

var signupTokenTTL time.Duration

// GetSignupTokenTTL - returns ttl of token
func (srv *TokenService) GetSignupTokenTTL() time.Duration {
	return signupTokenTTL
}

var resetPasswordTokenTTL time.Duration

// GetResetPasswordTokenTTL - returns ttl of token
func (srv *TokenService) GetResetPasswordTokenTTL() time.Duration {
	return resetPasswordTokenTTL
}

// CustomClaims is our custom metadata, which will be hashed
// and sent as the second segment in our JWT
type CustomClaims struct {
	User *userProto.User
	ID   string
	jwt.StandardClaims
}

// UserTokenIdentifier - used to store tokens s.t. we can validate them later
// also used to perform actions on them, eg. block them
type UserTokenIdentifier struct {
	TokenID   string    `bson:"token_id" json:"token_id"`
	UserID    string    `bson:"user_id" json:"user_id"`
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

// AuthIdentifier - used to keep track of auth logins
type AuthIdentifier struct {
	TokenID    string    `bson:"token_id" json:"token_id"`
	UserID     string    `bson:"user_id" json:"user_id"`
	Longitude  float64   `bson:"longitude" json:"longitude"`
	Latitude   float64   `bson:"latitude" json:"latitude"`
	Device     string    `bson:"device" json:"device"`
	TypeOf     string    `bson:"type_of" json:"type_of"`
	LastUsedAt time.Time `bson:"last_used_at" json:"last_used_at"`
	ExpiresAt  time.Time `bson:"expires_at" json:"expires_at"`
	CreatedAt  time.Time `bson:"created_at" json:"created_at"`
}

// TokenService - struct used to create tokens
type TokenService struct {
	authCollection  *mongo.Collection
	tokenCollection *mongo.Collection
	zapLog          *zap.Logger
}

func initCrypto() error {
	// Check if CRYPTO key exists
	jwtUserKey, check := os.LookupEnv("USER_CRYPTO_JWT_KEY")
	if !check {
		return errors.New("Missing USER_CRYPTO_JWT_KEY")
	}
	UserCryptoKey = []byte(jwtUserKey)

	// Check if CRYPTO key exists
	jwtResetPassowrdKey, check := os.LookupEnv("RESET_PASSWORD_CRYPTO_JWT_KEY")
	if !check {
		return errors.New("Missing RESET_PASSWORD_CRYPTO_JWT_KEY")
	}
	ResetPasswordCryptoKey = []byte(jwtResetPassowrdKey)

	// get auth history duration
	authTTLKey, check := os.LookupEnv("AUTH_HISTORY_TTL")
	if !check {
		return errors.New("Missing AUTH_HISTORY_TTL")
	}
	tempAuthHistoryTTL, err := time.ParseDuration(authTTLKey)
	if err != nil {
		return err
	}
	authHistoryTTL = tempAuthHistoryTTL

	// get user token ttl duration
	userTokenTTLKey, check := os.LookupEnv("USER_TOKEN_TTL")
	if !check {
		return errors.New("Missing USER_TOKEN_TTL")
	}
	tempUserTokenTTL, err := time.ParseDuration(userTokenTTLKey)
	if err != nil {
		return err
	}
	userTokenTTL = tempUserTokenTTL

	// get signup token ttl duration
	signupTokenTTLKey, check := os.LookupEnv("SIGNUP_TOKEN_TTL")
	if !check {
		return errors.New("Missing SIGNUP_TOKEN_TTL")
	}
	tempSignupTokenTTL, err := time.ParseDuration(signupTokenTTLKey)
	if err != nil {
		return err
	}
	signupTokenTTL = tempSignupTokenTTL

	// get reset pass ttl duration
	resetPasswordTTLKey, check := os.LookupEnv("RESET_PASS_TTL")
	if !check {
		return errors.New("Missing RESET_PASS_TTL")
	}
	tempResetPasswordTTLKey, err := time.ParseDuration(resetPasswordTTLKey)
	if err != nil {
		return err
	}
	resetPasswordTokenTTL = tempResetPasswordTTLKey

	return nil
}

// NewTokenService - returns a token service
func NewTokenService(authCollection *mongo.Collection, tokenCollection *mongo.Collection, zapLog *zap.Logger) (*TokenService, error) {
	if err := initCrypto(); err != nil {
		return nil, err
	}

	// create indexes for ttl for auth and token collection
	// setting expires after seconds to 0 makes mongodb look at the date, so that it expires
	// after it passed the date set in expires_at
	authModel := mongo.IndexModel{
		Keys:    bson.M{"expires_at": 1},
		Options: options.Index().SetExpireAfterSeconds(0),
	}
	_, err := authCollection.Indexes().CreateOne(context.Background(), authModel)
	if err != nil {
		zapLog.Error(fmt.Sprintf("Could not create index with err %v", err))
		return nil, err
	}

	tokenModel := mongo.IndexModel{
		Keys:    bson.M{"expires_at": 1},
		Options: options.Index().SetExpireAfterSeconds(0),
	}
	_, err = tokenCollection.Indexes().CreateOne(context.Background(), tokenModel)
	if err != nil {
		zapLog.Error(fmt.Sprintf("Could not create index with err %v", err))
		return nil, err
	}

	return &TokenService{authCollection, tokenCollection, zapLog}, nil
}

// MarshalAuthIdentifier - converts userProto.Auth to AuthIdentifier
func MarshalAuthIdentifier(authIdentifier *userProto.Auth) *AuthIdentifier {
	createdAt, _ := ptypes.Timestamp(authIdentifier.CreatedAt)
	expiresAt, _ := ptypes.Timestamp(authIdentifier.ExpiresAt)
	lastUsedAt, _ := ptypes.Timestamp(authIdentifier.LastUsedAt)
	return &AuthIdentifier{
		TokenID:    authIdentifier.TokenID,
		UserID:     authIdentifier.UserID,
		Longitude:  authIdentifier.Longitude,
		Latitude:   authIdentifier.Latitude,
		TypeOf:     authIdentifier.TypeOf,
		Device:     authIdentifier.Device,
		ExpiresAt:  expiresAt,
		CreatedAt:  createdAt,
		LastUsedAt: lastUsedAt,
	}
}

// UnmarshalAuthIdentifier - converts AuthIdentifier to userProto.Auth
func UnmarshalAuthIdentifier(authIdentifier *AuthIdentifier) *userProto.Auth {
	createdAt, _ := ptypes.TimestampProto(authIdentifier.CreatedAt)
	expiresAt, _ := ptypes.TimestampProto(authIdentifier.ExpiresAt)
	lastUsedAt, _ := ptypes.TimestampProto(authIdentifier.LastUsedAt)
	return &userProto.Auth{
		TokenID:    authIdentifier.TokenID,
		UserID:     authIdentifier.UserID,
		Longitude:  authIdentifier.Longitude,
		Latitude:   authIdentifier.Latitude,
		TypeOf:     authIdentifier.TypeOf,
		Device:     authIdentifier.Device,
		ExpiresAt:  expiresAt,
		CreatedAt:  createdAt,
		LastUsedAt: lastUsedAt,
	}
}

// BlockToken - add BlockToken id to database, so the token cannot be used anymore
func (srv *TokenService) BlockToken(ctx context.Context, tokenID string) error {
	// delete token
	_, err := srv.tokenCollection.DeleteOne(ctx, bson.M{"token_id": tokenID})
	if err != nil {
		return err
	}
	// also delete from auth history
	_, err = srv.authCollection.DeleteOne(ctx, bson.M{"token_id": tokenID})

	return nil
}

// BlockAllUserToken - block all users tokens.
func (srv *TokenService) BlockAllUserToken(ctx context.Context, userID string) error {
	// delete all users tokens token
	_, err := srv.tokenCollection.DeleteOne(ctx, bson.M{"user_id": userID})
	if err != nil {
		return err
	}
	// also delete all users auth history
	_, err = srv.authCollection.DeleteOne(ctx, bson.M{"user_id": userID})

	return nil
}

// Decode - decodes a token string into a token object
func (srv *TokenService) Decode(ctx context.Context, token string, key []byte) (*CustomClaims, error) {
	// Parse the token
	tokenType, err := jwt.ParseWithClaims(token, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	// Validate the token and return the custom claims
	if err := tokenType.Claims.Valid(); err != nil {
		return nil, err
	}
	if tokenType.Claims.(*CustomClaims).ID == "" {
		return nil, errors.New("token does not contain a valid id")
	}
	// check if token is blocked
	tokenIdentifier := UserTokenIdentifier{}
	if err := srv.tokenCollection.FindOne(ctx, bson.M{"token_id": tokenType.Claims.(*CustomClaims).ID}).Decode(&tokenIdentifier); err != nil {
		return nil, err
	}
	// check if the token is expired and delete if it is
	expirationTime := tokenIdentifier.ExpiresAt.Sub(time.Now()).Seconds()
	if expirationTime <= 0 {
		srv.zapLog.Warn(fmt.Sprintf("token is expired - deleting it from database with expiration time %d", expirationTime))
		srv.tokenCollection.DeleteOne(ctx, bson.M{"token_id": tokenIdentifier.TokenID})
		return nil, errors.New("token is expired - please login again")
	}

	// update auth history
	updateToken := bson.M{
		"$set": bson.M{
			"last_used_at": time.Now(),
		},
	}
	go srv.authCollection.UpdateOne(
		ctx,
		bson.M{"token_id": tokenType.Claims.(*CustomClaims).ID},
		updateToken,
	)

	return tokenType.Claims.(*CustomClaims), nil
}

// Encode - encodes a claim into a JWT
func (srv *TokenService) Encode(ctx context.Context, user *userProto.User, key []byte, expiresAt time.Duration) (string, error) {
	// Create the Claims
	id := uuid.NewV4().String()
	claims := CustomClaims{
		user,
		id,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiresAt).Unix(),
			Issuer:    "hqs.user.service",
		},
	}
	// add token to redis
	tokenIdentifier := UserTokenIdentifier{
		TokenID:   id,
		UserID:    user.Id,
		ExpiresAt: time.Now().Add(expiresAt),
		CreatedAt: time.Now(),
	}
	_, err := srv.tokenCollection.InsertOne(ctx, &tokenIdentifier)
	if err != nil {
		return "", err
	}
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	// Sign token and return
	return token.SignedString(key)
}

// GetAuthHistory - returns a users auth history
func (srv *TokenService) GetAuthHistory(ctx context.Context, user *userProto.User) ([]*userProto.Auth, error) {
	authHistory := []*userProto.Auth{}
	if user.Id == "" {
		return []*userProto.Auth{}, errors.New("User id is not valid")
	}

	// Find all documents that includes the user_id
	cursor, err := srv.authCollection.Find(ctx, bson.M{"user_id": user.Id})
	if err != nil {
		return []*userProto.Auth{}, err
	}

	for cursor.Next(context.Background()) {
		var tempAuth AuthIdentifier
		cursor.Decode(&tempAuth)
		// check if the auth is still valid - delete it if not
		expirationTime := tempAuth.ExpiresAt.Sub(time.Now()).Seconds()
		if expirationTime <= 0 {
			srv.zapLog.Warn(fmt.Sprintf("Deleting auth history document due to expiration date with expiration time: %d", expirationTime))
			go srv.tokenCollection.DeleteOne(ctx, bson.M{"token_id": tempAuth.TokenID})
			continue
		}
		authHistory = append(authHistory, UnmarshalAuthIdentifier(&tempAuth))
	}
	return authHistory, nil
}

// AddAuthToHistory - adds an authentication attempt to user history
func (srv *TokenService) AddAuthToHistory(ctx context.Context, user *userProto.User, token string, typeOf string, key []byte) error {
	// only accept correct type
	switch typeOf {
	case "login":
		break
	case "resetpassword":
		break
	default:
		return errors.New("Not a valid type")
	}
	// decode the token
	claims, err := srv.Decode(ctx, token, key)
	if err != nil {
		return err
	}

	// get longitude & latitude from context
	latitude := 0.0
	longitude := 0.0
	meta, ok := metadata.FromIncomingContext(ctx)
	if ok {
		latitudeString := meta["latitude"]
		longitudeString := meta["longitude"]
		if len(latitudeString) == 0 || len(longitudeString) == 0 || longitudeString[0] == "" || latitudeString[0] == "" {
			srv.zapLog.Warn("No latitude or longitude present")
		} else {
			tempLatitude, latitudeErr := strconv.ParseFloat(latitudeString[0], 64)
			tempLongitude, longitudeErr := strconv.ParseFloat(longitudeString[0], 64)
			if latitudeErr != nil || longitudeErr != nil {
				srv.zapLog.Warn("Could not convert latitude or longitude from string to float")
			} else {
				latitude = tempLatitude
				longitude = tempLongitude
			}
		}
	} else {
		srv.zapLog.Warn("Could not get context")
	}

	// get device information
	deviceInformation := "Unknown"
	meta, ok = metadata.FromIncomingContext(ctx)
	if ok {
		deviceString := meta["device"]
		if len(deviceString) == 0 || deviceString[0] == "" {
			srv.zapLog.Warn("No device information present")
		} else {
			deviceInformation = deviceString[0]
		}
	}

	// create new token history point
	auth := &AuthIdentifier{
		Longitude:  longitude,
		Latitude:   latitude,
		TokenID:    claims.ID,
		Device:     deviceInformation,
		TypeOf:     typeOf,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(authHistoryTTL),
		LastUsedAt: time.Now(),
		UserID:     user.Id,
	}

	// send the auth attempt to the database
	_, err = srv.authCollection.InsertOne(ctx, auth)
	if err != nil {
		return err
	}

	return nil
}

// DeleteUserAuthHistory - deletes all the auth history of a user
func (srv *TokenService) DeleteUserAuthHistory(ctx context.Context, user *userProto.User) error {
	_, err := srv.authCollection.DeleteMany(ctx, bson.M{"user_id": user.Id})
	if err != nil {
		return err
	}
	return nil
}

// DeleteUserTokenHistory - deletes all the auth history of a user
func (srv *TokenService) DeleteUserTokenHistory(ctx context.Context, user *userProto.User) error {
	_, err := srv.tokenCollection.DeleteMany(ctx, bson.M{"user_id": user.Id})
	if err != nil {
		return err
	}
	return nil
}
