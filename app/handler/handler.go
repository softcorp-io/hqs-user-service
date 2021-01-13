package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	crypto "github.com/softcorp-io/hqs-user-service/crypto"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/metadata"

	repository "github.com/softcorp-io/hqs-user-service/repository"
	storage "github.com/softcorp-io/hqs-user-service/storage"
	emailProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_email_service"
	privilegeProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_privilege_service"
	userProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
)

// authable - interface used to decode/encode tokens.
type authable interface {
	Decode(ctx context.Context, token string, key []byte) (*crypto.CustomClaims, error)
	Encode(ctx context.Context, user *userProto.User, key []byte, expiresAt time.Duration) (string, error)
	BlockToken(ctx context.Context, tokenID string) error
	BlockAllUserToken(ctx context.Context, userID string) error
	GetAuthHistory(ctx context.Context, user *userProto.User) ([]*userProto.Auth, error)
	AddAuthToHistory(ctx context.Context, user *userProto.User, token string, success bool, typeOf string, key []byte) error
	DeleteUserAuthHistory(ctx context.Context, user *userProto.User) error
	DeleteUserTokenHistory(ctx context.Context, user *userProto.User) error
	GetResetPasswordCryptoKey() []byte
	GetUserCryptoKey() []byte
	GetUserTokenTTL() time.Duration
	GetSignupTokenTTL() time.Duration
	GetResetPasswordTokenTTL() time.Duration
	GetAuthHistoryTTL() time.Duration
}

// Handler - struct used through program and passed to go-micro.
type Handler struct {
	repository      repository.Repository
	storage         storage.Storage
	crypto          authable
	emailClient     emailProto.EmailServiceClient
	privilegeClient privilegeProto.PrivilegeServiceClient
	zapLog          *zap.Logger
}

// NewHandler returns a Handler object
func NewHandler(repo repository.Repository, stor storage.Storage, crypto authable, emailClient emailProto.EmailServiceClient, privilegeClient privilegeProto.PrivilegeServiceClient, zapLog *zap.Logger) *Handler {
	return &Handler{repo, stor, crypto, emailClient, privilegeClient, zapLog}
}

// Ping - used for other service to check if live
func (s *Handler) Ping(ctx context.Context, req *userProto.Request) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")
	return &userProto.Response{}, nil
}

// Create - creates a new user. Parent user has to be logged in in order to create.
// Furthermore the authUser has to be allowed to create.
func (s *Handler) Create(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		CreateUser: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	// create user
	resultUser := repository.MarshalUser(req)

	if err := resultUser.Validate("password"); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate user with err %v", err))
		return &userProto.Response{}, err
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(resultUser.Password), bcrypt.DefaultCost)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get hash password with err %v", err))
		return &userProto.Response{}, err
	}

	resultUser.Password = string(hashedPass)
	if err := s.repository.Create(ctx, resultUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not create with err %v", err))
		return &userProto.Response{}, err
	}

	// Strip the password back out, so's we're not returning it
	res := &userProto.Response{}
	resultUser.Password = ""
	res.User = repository.UnmarshalUser(resultUser)

	return res, nil
}

// GenerateSignupToken - generates a token another user can use to singup with. This token has
// some values set. Specifically it needs AllowView, AllowCreate, AllowPermission & AllowDelete.
// it uses a uuid, so that it can only be used once. Default expiration time is 3 days
func (s *Handler) GenerateSignupToken(ctx context.Context, req *userProto.User) (*userProto.Token, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		CreateUser: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Token{}, err
	}

	req.Id = uuid.NewV4().String()

	token, err := s.crypto.Encode(context.Background(), req, s.crypto.GetUserCryptoKey(), s.crypto.GetSignupTokenTTL())
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not encode signup with err %v", err))
		return &userProto.Token{}, err
	}

	// find reset password link
	linkBase, ok := os.LookupEnv("EMAIL_SIGNUP_LINK_BASE")
	if !ok {
		s.zapLog.Error("Could not find signup link EMAIL_SIGNUP_LINK_BASE")
		return &userProto.Token{}, err
	}

	// return result and add url to link
	res := &userProto.Token{}
	res.Url = linkBase
	res.Token = token

	return res, nil
}

// Signup - creates a new user. Given is a user and a token inside RequestSignup. First the token is used
// to verify that the user is allowed to create a user. Then the id is transfered to the new user, so a token
// only can be used once. Third, we build the user with the allowances from the token and the information from
// user
func (s *Handler) Signup(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that the user is allowed to signup
	userToken, err := s.validateSignupToken(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	_, err = s.repository.Get(ctx, repository.MarshalUser(userToken))
	if err == nil {
		s.zapLog.Error("Token already used to signup with")
		return &userProto.Response{}, errors.New("token already used to signup with")
	}

	// build user
	createUser := req

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(createUser.Password), bcrypt.DefaultCost)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not generate hash with err %v", err))
		return &userProto.Response{}, err
	}

	// set default values
	defaultPrivResponse, err := s.privilegeClient.GetDefault(ctx, &privilegeProto.Request{})
	if err != nil {
		return &userProto.Response{}, err
	}

	createUser.Password = string(hashedPass)
	createUser.Id = userToken.Id
	createUser.PrivilegeID = defaultPrivResponse.Privilege.Id

	if err := s.repository.Signup(ctx, repository.MarshalUser(createUser)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not signup with err %v", err))
		return &userProto.Response{}, err
	}

	// Strip the password back out, so's we're not returning it
	res := &userProto.Response{}
	createUser.Password = ""
	res.User = createUser

	return res, nil
}

// Get - gets a single user. Only uses the requested users id
// AuthUser has to be allowed to see users
func (s *Handler) Get(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		ViewAllUsers: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	user, err := s.repository.Get(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get user with err %v", err))
		return &userProto.Response{}, err
	}

	// the root user cannot be seen
	if user.Admin {
		s.zapLog.Error("Tried to get root user")
		return &userProto.Response{}, errors.New("Root user is not getable")
	}

	// set user image
	imageURL, err := s.storage.Get(user.Image, time.Hour*1)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get user image from storage with err %v", err))
	} else {
		user.Image = imageURL
	}

	resultUser := repository.UnmarshalUser(user)

	// return result
	res := &userProto.Response{}
	resultUser.Password = ""
	res.User = resultUser

	return res, nil
}

// GetByToken - get user information by its token. Return all user information
func (s *Handler) GetByToken(ctx context.Context, req *userProto.Request) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	actualUser, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		CreateUser: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	// set user image
	imageURL, err := s.storage.Get(actualUser.Image, time.Hour*1)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get user image from storage with err %v", err))
	} else {
		actualUser.Image = imageURL
	}

	res := &userProto.Response{}
	actualUser.Password = ""
	res.User = actualUser

	return res, nil
}

// GetByEmail - find a user by searching for his/her email. Token is required
// AuthUser has to be allowed to see users
func (s *Handler) GetByEmail(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		CreateUser: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	user, err := s.repository.GetByEmail(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get user with err %v", err))
		return &userProto.Response{}, err
	}

	// set user image
	imageURL, err := s.storage.Get(user.Image, time.Hour*1)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get user image from storage with err %v", err))
	} else {
		user.Image = imageURL
	}

	resultUser := repository.UnmarshalUser(user)

	// return result
	res := &userProto.Response{}
	resultUser.Password = ""
	res.User = resultUser

	return res, nil
}

// GetAll - returns all users. Token is required
// AuthUser has to be allowed to see users
func (s *Handler) GetAll(ctx context.Context, req *userProto.Request) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		CreateUser: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	results, err := s.repository.GetAll(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get all user with err %v", err))
		return &userProto.Response{}, err
	}

	for _, user := range results {
		// strip password
		user.Password = ""

		// add user image
		imageURL, err := s.storage.Get(user.Image, time.Hour*1)
		if err != nil {
			s.zapLog.Error(fmt.Sprintf("Could not get user image from storage with err %v", err))
		} else {
			user.Image = imageURL
		}
	}

	resultUsers := repository.UnmarshalUserCollection(results)

	// all users passwords are stripped in repository - faster
	// return result
	res := &userProto.Response{}
	res.Users = resultUsers

	return res, nil
}

// UpdateProfile - updates profile information given a token. Token is used to validate and find the user
// A user can only update his/her own profile
func (s *Handler) UpdateProfile(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	actualUser, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	resultUser := repository.MarshalUser(req)

	// give user the id from the token
	resultUser.ID = actualUser.Id

	if err := s.repository.UpdateProfile(ctx, resultUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not update profile with err  %v", err))
		return &userProto.Response{}, err
	}

	// return result
	res := &userProto.Response{}
	resultUser.Password = ""
	res.User = repository.UnmarshalUser(resultUser)

	return res, nil
}

// UpdatePrivileges - updates a users privileges. This is done by assigning the correct id to privilege struct.
func (s *Handler) UpdatePrivileges(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		ManagePrivileges: true,
	})

	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	resultUser := repository.MarshalUser(req)

	// validate that user actually exists & that reqUser is no admin
	reqUser, err := s.repository.Get(ctx, resultUser)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get reqUser with err  %v", err))
		return &userProto.Response{}, err
	}

	// the root user cannot be updated
	if reqUser.Admin {
		s.zapLog.Error("Tried to update root user")
		return &userProto.Response{}, errors.New("Root user is not updateable")
	}

	// check that the requested prvilege actully exusts
	privilege, err := s.privilegeClient.Get(ctx, &privilegeProto.Privilege{
		Id: req.PrivilegeID,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not find the specified privilege with err  %v", err))
		return &userProto.Response{}, err
	}

	// update user with privilege id
	resultUser.PrivilegeID = privilege.Privilege.Id

	if err := s.repository.UpdatePrivileges(ctx, resultUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not update with err  %v", err))
		return &userProto.Response{}, err
	}

	// return result
	res := &userProto.Response{}
	resultUser.Password = ""
	res.User = repository.UnmarshalUser(resultUser)

	return res, nil

}

// UpdatePassword - updates password given a token. The token is used to vaidate and find the user
// A user can only update his/her own password
func (s *Handler) UpdatePassword(ctx context.Context, req *userProto.UpdatePasswordRequest) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	actualUser, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	// validate that the user remembers his/her old password
	if err := bcrypt.CompareHashAndPassword([]byte(actualUser.Password), []byte(req.OldPassword)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not compare hash with err  %v", err))
		return &userProto.Response{}, err
	}

	// validate password
	resultUser := &repository.User{
		Password: req.NewPassword,
	}

	if err := resultUser.Validate("password"); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate user password with err %v", err))
		return &userProto.Response{}, err
	}

	// hash the password
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not generate hash with err %v", err))
		return &userProto.Response{}, err
	}

	resultUser.Password = string(hashedPass)

	// give user the id from the toke
	resultUser.ID = actualUser.Id

	if err := s.repository.UpdatePassword(ctx, resultUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not update password with err %v", err))
		return &userProto.Response{}, err
	}

	// return result
	res := &userProto.Response{}
	resultUser.Password = ""
	res.User = repository.UnmarshalUser(resultUser)

	return res, nil
}

// UpdateBlockUser - can either block a user or unblock a user
// block = true, not blocked = false.
func (s *Handler) UpdateBlockUser(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		BlockUser: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	// validate that user actually exists & that reqUser is no admin
	reqUser, err := s.repository.Get(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get reqUser with err  %v", err))
		return &userProto.Response{}, err
	}

	// the root user cannot be updated
	if reqUser.Admin {
		s.zapLog.Error("Tried to update root user")
		return &userProto.Response{}, errors.New("Root user is not updateable")
	}

	if err := s.repository.UpdateBlockUser(ctx, repository.MarshalUser(req)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Unable to block user with err %v", err))
		return &userProto.Response{}, err
	}

	res := &userProto.Response{}
	res.User = req

	return res, nil
}

// UploadImage - gets an image from a user and uploads it to s3 store
func (s *Handler) UploadImage(stream userProto.UserService_UploadImageServer) error {
	s.zapLog.Info("Recieved new request")

	// authenticate
	req, err := stream.Recv()
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not recieve auth stream recv() with err %v", err))
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token := req.GetToken()

	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewIncomingContext(ctx, md)

	authUser, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return err
	}

	maxSize := 1 << 40

	imageData := bytes.Buffer{}
	imageSize := 0

	for {
		s.zapLog.Info("Waiting to receive more data...")
		req, err := stream.Recv()
		if err == io.EOF {
			s.zapLog.Info("EOR no more data data...")
			break
		}
		if err != nil {
			s.zapLog.Error(fmt.Sprintf("Could not reviece chunk data stream recv() with err %v", err))
			return err
		}
		chunk := req.GetChunkData()
		size := len(chunk)

		imageSize += size
		if imageSize > maxSize {
			s.zapLog.Error(fmt.Sprintf("Image size is too large: %d", imageSize))
			return errors.New("Image size too large")
		}

		s.zapLog.Info(fmt.Sprintf("received new chunk with size: %d total size: %d", size, imageSize))

		_, err = imageData.Write(chunk)
		if err != nil {
			s.zapLog.Error(fmt.Sprintf("Could not write imageData to buffer with err %v", err))
			return err
		}
	}

	// upload first so we don't send success on failure
	imagePath := "hqs/users/" + actualUser.ID + "profileImage/profileImage.png"
	if err := s.storage.Upload(imageData, imagePath, "image/jpeg", "image/png", "image/jpg"); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not upload image to storage with err %v", err))
		return err
	}

	// update user image in repo
	actualUser.Image = imagePath
	if err := s.repository.UpdateImage(context.Background(), actualUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not update repository with image path %v", err))
		return err
	}

	res := &userProto.UploadImageResponse{
		Size: uint32(imageSize),
	}

	// send response and close
	if err := stream.SendAndClose(res); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not send and close image stream with image path %v", err))
		return err
	}

	s.zapLog.Info("Image successfully uploaded!")

	return nil
}

// Delete - deletes all users. At the moment, you can only delete your own user
func (s *Handler) Delete(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		DeleteUser: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	deleteUser, err := s.repository.Get(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get deleteUser with err  %v", err))
		return &userProto.Response{}, err
	}

	// the root user cannot be deleted
	if deleteUser.Admin {
		s.zapLog.Error("Tried to delete root user")
		return &userProto.Response{}, errors.New("Root user is not deletable")
	}

	// Delete the user
	if err := s.repository.Delete(ctx, deleteUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete user from repository with err %v", err))
		return &userProto.Response{}, err
	}

	// also delete users auth history
	if err := s.crypto.DeleteUserAuthHistory(ctx, req); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete users auth history from crypto with err %v", err))
	}

	// same with token history
	if err := s.crypto.DeleteUserTokenHistory(ctx, req); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete users auth history from crypto with err %v", err))
	}

	// delete users profile image todo: add this to storage insted... should not be part of handler
	// if the user didn't update profile image
	if strings.Contains(deleteUser.Image, "shared") {
		return &userProto.Response{}, nil
	}

	if err := s.storage.Delete(deleteUser.Image); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete user image from storage with err %v", err))
		return &userProto.Response{}, err
	}

	if err := s.storage.Delete("hqs/users/" + deleteUser.ID + "/profileImage"); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete image folder from storage with err %v", err))
		return &userProto.Response{}, err
	}

	if err := s.storage.Delete("hqs/users/" + deleteUser.ID); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete user folder from storage with err %v", err))
		return &userProto.Response{}, err
	}

	return &userProto.Response{}, nil
}

// Auth - authenticates a user, given that users email and password. Returns a token
func (s *Handler) Auth(ctx context.Context, req *userProto.User) (*userProto.Token, error) {
	s.zapLog.Info("Recieved new request")

	user, err := s.repository.GetByEmail(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &userProto.Token{}, err
	}

	// check if the user is blocked
	if user.Blocked {
		s.zapLog.Error("The user is blocked")
		return &userProto.Token{}, errors.New("The user is blocked")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not compare hash with err  %v", err))
		return &userProto.Token{}, err
	}

	token, err := s.crypto.Encode(context.Background(), repository.UnmarshalUser(user), s.crypto.GetUserCryptoKey(), s.crypto.GetUserTokenTTL())
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not encode user with err  %v", err))
		return &userProto.Token{}, err
	}

	// todo: change longiture and lattitude
	if err = s.crypto.AddAuthToHistory(ctx, repository.UnmarshalUser(user), token, true, "auth", s.crypto.GetUserCryptoKey()); err != nil {
		s.zapLog.Warn(fmt.Sprintf("Could not add to auth history with err : %v", err))
	}

	// return result
	res := &userProto.Token{}
	res.Token = token

	return res, nil
}

// BlockToken - block token so it cannot be used anymore. Can be undone the next hour
func (s *Handler) BlockToken(ctx context.Context, req *userProto.Token) (*userProto.Token, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	actualUser, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Token{}, err
	}

	claims, err := s.crypto.Decode(context.Background(), req.Token, s.crypto.GetUserCryptoKey())
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not decode token with err  %v", err))
		return &userProto.Token{}, err
	}

	if claims.User.Id != actualUser.Id {
		s.zapLog.Error("Token user does not match auth user")
		return &userProto.Token{}, errors.New("Token user does not match auth user")
	}

	if err := s.crypto.BlockToken(context.Background(), claims.ID); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not block token with err  %v", err))
		return &userProto.Token{}, err
	}

	// return result
	res := &userProto.Token{}
	res.Valid = false
	return res, nil
}

// EmailResetPasswordToken - generates a token and email it to the specifc user.
func (s *Handler) EmailResetPasswordToken(ctx context.Context, req *userProto.User) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	_, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{
		SendResetPasswordEmail: true,
	})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	// also implictly checks that req contains an id which we use in resetPassword
	resultUser, err := s.repository.Get(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not find user with err %v", err))
		return &userProto.Response{}, err
	}

	// generate token
	resetToken, err := s.crypto.Encode(context.Background(), req, s.crypto.GetResetPasswordCryptoKey(), s.crypto.GetResetPasswordTokenTTL())
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not encode reset password with err %v", err))
		return &userProto.Response{}, err
	}

	// todo: change longiture and lattitude
	if err = s.crypto.AddAuthToHistory(ctx, repository.UnmarshalUser(resultUser), resetToken, true, "reset password", s.crypto.GetResetPasswordCryptoKey()); err != nil {
		s.zapLog.Warn(fmt.Sprintf("Could not add to auth history with err : %v", err))
	}

	// send email
	_, err = s.emailClient.SendResetPasswordEmail(ctx, &emailProto.ResetPasswordEmail{
		Name:  resultUser.Name,
		To:    []string{resultUser.Email},
		Token: resetToken,
	})

	if err != nil {
		s.zapLog.Error("Could not send email to user")
		return &userProto.Response{}, errors.New("Could not send reset password email to user")
	}

	// return result
	return &userProto.Response{}, nil
}

// ResetPassword - a user can reset his password if he has a valid reset password token.
func (s *Handler) ResetPassword(ctx context.Context, req *userProto.ResetPasswordRequest) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that the reset token is valid
	claims, err := s.crypto.Decode(context.Background(), req.Token, s.crypto.GetResetPasswordCryptoKey())
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not decode reset token with err %v", err))
		return &userProto.Response{}, err
	}

	// check that it actually contains a user
	if claims.User.Id == "" {
		s.zapLog.Error("Invalid user")
		return &userProto.Response{}, errors.New("Invalid user")
	}

	// update the password of the claimed user
	updateUser := repository.MarshalUser(claims.User)
	updateUser.Password = req.NewPassword
	if err := s.repository.UpdatePassword(ctx, updateUser); err == nil {
		s.zapLog.Error("Could not update the user with that password")
		return &userProto.Response{}, err
	}

	// when password is updated, block token
	if err := s.crypto.BlockToken(ctx, claims.ID); err != nil {
		s.zapLog.Error("Could not block the token, the user gave to reset his password")
		return &userProto.Response{}, err
	}

	return &userProto.Response{}, nil
}

// BlockTokenByID - block token so it cannot be used anymore
func (s *Handler) BlockTokenByID(ctx context.Context, req *userProto.BlockTokenRequest) (*userProto.Token, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	actualUser, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Token{}, err
	}

	// check if the user has rights to the token
	authHistory, err := s.crypto.GetAuthHistory(context.Background(), actualUser)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get auth history with err  %v", err))
		return &userProto.Token{}, err
	}

	// check if user is allowed to block the token
	allowed := false
	for _, auth := range authHistory {
		if auth.TokenID == req.TokenID {
			allowed = true
			break
		}
	}

	if !allowed {
		s.zapLog.Error("Token not present or user not allowed to block it")
		return &userProto.Token{}, errors.New("Token not present or user not allowed to block it")
	}

	if err := s.crypto.BlockToken(context.Background(), req.TokenID); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not block token with err  %v", err))
		return &userProto.Token{}, err
	}

	// return result
	res := &userProto.Token{}
	res.Valid = false
	return res, nil
}

// BlockUsersTokens - block all users token
func (s *Handler) BlockUsersTokens(ctx context.Context, req *userProto.Request) (*userProto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	actualUser, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.Response{}, err
	}

	if err := s.crypto.BlockAllUserToken(context.Background(), actualUser.Id); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not block all users tokens with err  %v", err))
		return &userProto.Response{}, err
	}

	// return result
	res := &userProto.Response{}
	res.Success = true
	return res, nil
}

// GetAuthHistory - returns the last 24 hour auth history of a user
func (s *Handler) GetAuthHistory(ctx context.Context, req *userProto.Request) (*userProto.AuthHistory, error) {
	s.zapLog.Info("Recieved new request")

	// check that user is allowed to create
	actualUser, err := s.validateTokenHelper(ctx, &privilegeProto.Privilege{})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &userProto.AuthHistory{}, err
	}

	// get token history
	authHistory, err := s.crypto.GetAuthHistory(context.Background(), actualUser)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get auth history with err  %v", err))
		return &userProto.AuthHistory{}, err
	}

	// return result
	res := &userProto.AuthHistory{}
	res.AuthHistory = authHistory
	return res, nil
}

// ValidateToken - validates a users token
func (s *Handler) ValidateToken(ctx context.Context, req *userProto.Token) (*userProto.Token, error) {
	s.zapLog.Info("Recieved new request")

	claims, err := s.crypto.Decode(context.Background(), req.Token, s.crypto.GetUserCryptoKey())
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not decode token with err  %v", err))
		return &userProto.Token{}, err
	}

	if claims.User.Id == "" {
		s.zapLog.Error("Invalid user")
		return &userProto.Token{}, errors.New("Invalid user")
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(claims.User))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &userProto.Token{}, err
	}

	if actualUser.Blocked {
		s.zapLog.Error("User is blocked")
		return &userProto.Token{}, errors.New("User is blocked")
	}

	// get users privileges
	privilegeResponse, err := s.privilegeClient.Get(ctx, &privilegeProto.Privilege{Id: actualUser.PrivilegeID})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get users privileges with err %v", err))
		return &userProto.Token{}, err
	}

	// return result
	res := &userProto.Token{}
	res.ManagePrivileges = privilegeResponse.Privilege.ManagePrivileges
	res.Valid = true
	return res, nil
}

// validateSignupToken - used for validating the crypto token by sigup function
func (s *Handler) validateSignupToken(ctx context.Context) (*userProto.User, error) {
	meta, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		s.zapLog.Error("Could not validate token")
		return nil, errors.New("Could not validate token")
	}

	token := meta["token"]

	if len(token) == 0 {
		s.zapLog.Error("Missing token header in context")
		return nil, errors.New("Missing token header in context")
	}

	if strings.Trim(token[0], " ") == "" {
		s.zapLog.Error("Token is empty")
		return nil, errors.New("Token is empty")
	}

	claims, err := s.crypto.Decode(context.Background(), token[0], s.crypto.GetUserCryptoKey())
	if err != nil {
		return nil, err
	}

	if claims.User.Id == "" {
		s.zapLog.Error("Invalid user")
		return nil, errors.New("Invalid user")
	}
	return claims.User, nil
}

// validateTokenHelper - helper function to validate tokens inside functions in Handler
func (s *Handler) validateTokenHelper(ctx context.Context, privilege *privilegeProto.Privilege) (*userProto.User, error) {
	meta, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		s.zapLog.Error("Could not validate token")
		return nil, errors.New("Could not validate token")
	}

	token := meta["token"]

	if len(token) == 0 {
		s.zapLog.Error("Missing token header in context")
		return nil, errors.New("Missing token header in context")
	}

	if strings.Trim(token[0], " ") == "" {
		s.zapLog.Error("Token is empty")
		return nil, errors.New("Token is empty")
	}

	claims, err := s.crypto.Decode(context.Background(), token[0], s.crypto.GetUserCryptoKey())
	if err != nil {
		return nil, err
	}

	if claims.User.Id == "" {
		s.zapLog.Error("Invalid user")
		return nil, errors.New("Invalid user")
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(claims.User))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return nil, err
	}

	if actualUser.Blocked {
		s.zapLog.Error("User is blocked")
		return nil, errors.New("User is blocked")
	}

	// get users privileges
	privilegeResponse, err := s.privilegeClient.Get(ctx, &privilegeProto.Privilege{Id: actualUser.PrivilegeID})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get users privileges with err %v", err))
		return nil, err
	}

	// check if we desire the privilege, we also have it
	resultPrivilege := privilegeResponse.Privilege
	if privilege.ViewAllUsers && !resultPrivilege.ViewAllUsers {
		s.zapLog.Error("User do not have view privileges")
		return nil, errors.New("User do not have view privileges")
	}
	if privilege.CreateUser && !resultPrivilege.CreateUser {
		s.zapLog.Error("User do not have create privileges")
		return nil, errors.New("User do not have create privileges")
	}
	if privilege.ManagePrivileges && !resultPrivilege.ManagePrivileges {
		s.zapLog.Error("User do not have manage privileges")
		return nil, errors.New("User do not have manage privileges")
	}
	if privilege.DeleteUser && !resultPrivilege.DeleteUser {
		s.zapLog.Error("User do not have delete privileges")
		return nil, errors.New("User do not have delete privileges")
	}
	if privilege.BlockUser && !resultPrivilege.BlockUser {
		s.zapLog.Error("User do not have block privileges")
		return nil, errors.New("User do not have block privileges")
	}
	if privilege.SendResetPasswordEmail && !resultPrivilege.SendResetPasswordEmail {
		s.zapLog.Error("User do not have send reset email privileges")
		return nil, errors.New("User do not have send reset email privileges")
	}

	return repository.UnmarshalUser(actualUser), nil
}
