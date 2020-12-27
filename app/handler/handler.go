package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/metadata"

	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
	repository "github.com/softcorp-io/hqs_user_service/repository"
	service "github.com/softcorp-io/hqs_user_service/service"
	storage "github.com/softcorp-io/hqs_user_service/storage"
)

// authable - interface used to decode/encode tokens.
type authable interface {
	Decode(ctx context.Context, token string) (*service.CustomClaims, error)
	Encode(ctx context.Context, user *proto.User) (string, error)
	BlockToken(ctx context.Context, tokenID string) error
	BlockAllUserToken(ctx context.Context, userID string) error
	GetAuthHistory(ctx context.Context, user *proto.User) ([]*proto.Auth, error)
	AddAuthToHistory(ctx context.Context, user *proto.User, token string, success bool) error
	DeleteUserAuthHistory(ctx context.Context, user *proto.User) error
	DeleteUserTokenHistory(ctx context.Context, user *proto.User) error
}

// Handler - struct used through program and passed to go-micro.
type Handler struct {
	repository   repository.Repository
	storage      storage.Storage
	tokenService authable
	zapLog       *zap.Logger
}

// NewHandler returns a Handler object
func NewHandler(repo repository.Repository, stor storage.Storage, tokenService authable, zapLog *zap.Logger) *Handler {
	return &Handler{repo, stor, tokenService, zapLog}
}

// Create - creates a new user. Parent user has to be logged in in order to create.
// Furthermore the authUser has to be allowed to create.
func (s *Handler) Create(ctx context.Context, req *proto.User) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")
	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	if actualUser.AllowCreate != true {
		s.zapLog.Error("User not allowed to create")
		return &proto.Response{}, errors.New("User not allowed to create")
	}

	resultUser := repository.MarshalUser(req)

	if err := resultUser.Validate("password"); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate user with err %v", err))
		return &proto.Response{}, err
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(resultUser.Password), bcrypt.DefaultCost)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get hash password with err %v", err))
		return &proto.Response{}, err
	}

	resultUser.Password = string(hashedPass)
	if err := s.repository.Create(ctx, resultUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not create with err %v", err))
		return &proto.Response{}, err
	}

	// Strip the password back out, so's we're not returning it
	res := &proto.Response{}
	resultUser.Password = ""
	res.User = repository.UnmarshalUser(resultUser)

	return res, nil
}

// GenerateSignupToken - generates a token another user can use to singup with. This token has
// some values set. Specifically it needs AllowView, AllowCreate, AllowPermission & AllowDelete.
// it uses a uuid, so that it can only be used once. Default expiration time is 3 days
func (s *Handler) GenerateSignupToken(ctx context.Context, req *proto.User) (*proto.Token, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Token{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get usee with err %v", err))
		return &proto.Token{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Token{}, errors.New("The user is blocked")
	}

	if actualUser.AllowCreate != true {
		s.zapLog.Error("User not allowed")
		return &proto.Token{}, errors.New("User not allowed to create")
	}

	reqUser := repository.MarshalUser(req)
	if err := reqUser.ValidateAllowances(); err != nil {
		s.zapLog.Error(fmt.Sprintf("User allowances are not correct with err %v", err))
		return &proto.Token{}, err
	}

	req.Id = uuid.NewV4().String()

	token, err := s.tokenService.Encode(context.Background(), req)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not encode signup with err %v", err))
		return &proto.Token{}, err
	}

	// return result
	res := &proto.Token{}
	res.Token = token

	return res, nil
}

// Signup - creates a new user. Given is a user and a token inside RequestSignup. First the token is used
// to verify that the user is allowed to create a user. Then the id is transfered to the new user, so a token
// only can be used once. Third, we build the user with the allowances from the token and the information from
// user
func (s *Handler) Signup(ctx context.Context, req *proto.User) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	// check that the user is allowed to signup
	userToken, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	_, err = s.repository.Get(ctx, repository.MarshalUser(userToken))
	if err == nil {
		s.zapLog.Error("Token already used to signup with")
		return &proto.Response{}, errors.New("token already used to signup with")
	}

	// build user
	createUser := req

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(createUser.Password), bcrypt.DefaultCost)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not generate hash with err %v", err))
		return &proto.Response{}, err
	}

	createUser.Password = string(hashedPass)
	createUser.Id = userToken.Id
	createUser.AllowView = userToken.AllowView
	createUser.AllowCreate = userToken.AllowCreate
	createUser.AllowPermission = userToken.AllowPermission
	createUser.AllowDelete = userToken.AllowDelete
	createUser.AllowBlock = userToken.AllowBlock
	createUser.Blocked = userToken.Blocked

	s.zapLog.Info(fmt.Sprintf("Create user blocked: ", userToken.Blocked))

	if err := s.repository.Signup(ctx, repository.MarshalUser(createUser)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not signup with err %v", err))
		return &proto.Response{}, err
	}

	// Strip the password back out, so's we're not returning it
	res := &proto.Response{}
	createUser.Password = ""
	res.User = createUser

	return res, nil
}

// Get - gets a single user. Only uses the requested users id
// AuthUser has to be allowed to see users
func (s *Handler) Get(ctx context.Context, req *proto.User) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	if actualUser.AllowView != true {
		s.zapLog.Error("User not allowed to view")
		return &proto.Response{}, errors.New("user not allowed to view")
	}

	user, err := s.repository.Get(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get user with err %v", err))
		return &proto.Response{}, err
	}

	// the root user cannot be seen
	if user.Admin {
		s.zapLog.Error("Tried to get root user")
		return &proto.Response{}, errors.New("Root user is not getable")
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
	res := &proto.Response{}
	resultUser.Password = ""
	res.User = resultUser

	return res, nil
}

// GetByToken - get user information by its token. Return all user information
func (s *Handler) GetByToken(ctx context.Context, req *proto.Request) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	// set user image
	imageURL, err := s.storage.Get(actualUser.Image, time.Hour*1)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get user image from storage with err %v", err))
	} else {
		actualUser.Image = imageURL
	}

	resultUser := repository.UnmarshalUser(actualUser)

	res := &proto.Response{}
	resultUser.Password = ""
	res.User = resultUser

	return res, nil
}

// GetByEmail - find a user by searching for his/her email. Token is required
// AuthUser has to be allowed to see users
func (s *Handler) GetByEmail(ctx context.Context, req *proto.User) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	if actualUser.AllowView != true {
		s.zapLog.Error("User not allowed to view")
		return &proto.Response{}, errors.New("user not allowed to view")
	}

	user, err := s.repository.GetByEmail(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get user with err %v", err))
		return &proto.Response{}, err
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
	res := &proto.Response{}
	resultUser.Password = ""
	res.User = resultUser

	return res, nil
}

// GetAll - returns all users. Token is required
// AuthUser has to be allowed to see users
func (s *Handler) GetAll(ctx context.Context, req *proto.Request) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	if actualUser.AllowView != true {
		s.zapLog.Error("User not allowed to view")
		return &proto.Response{}, errors.New("user not allowed to view")
	}

	results, err := s.repository.GetAll(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get all user with err %v", err))
		return &proto.Response{}, err
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
	res := &proto.Response{}
	res.Users = resultUsers

	return res, nil
}

// UpdateProfile - updates profile information given a token. Token is used to validate and find the user
// A user can only update his/her own profile
func (s *Handler) UpdateProfile(ctx context.Context, req *proto.User) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	// the root user cannot be seen
	if actualUser.Admin {
		s.zapLog.Error("Tried to update root user")
		return &proto.Response{}, errors.New("Root user is not updateable")
	}

	resultUser := repository.MarshalUser(req)

	// give user the id from the token
	resultUser.ID = actualUser.ID

	if err := s.repository.UpdateProfile(ctx, resultUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not update profile with err  %v", err))
		return &proto.Response{}, err
	}

	// return result
	res := &proto.Response{}
	resultUser.Password = ""
	res.User = repository.UnmarshalUser(resultUser)

	return res, nil
}

// UpdateAllowances - updates a users allowance. Can only be done with a user with rights to do so
func (s *Handler) UpdateAllowances(ctx context.Context, req *proto.User) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	if actualUser.AllowPermission != true {
		s.zapLog.Error("User not allowed to update other users permissions")
		return &proto.Response{}, errors.New("User not allowed to update other users permissions")
	}

	resultUser := repository.MarshalUser(req)

	// validate that user actually exists & that reqUser is no admin
	reqUser, err := s.repository.Get(ctx, resultUser)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get reqUser with err  %v", err))
		return &proto.Response{}, err
	}

	// the root user cannot be updated
	if reqUser.Admin {
		s.zapLog.Error("Tried to update root user")
		return &proto.Response{}, errors.New("Root user is not updateable")
	}

	// a user cannot update his/her own allowances if he/she do not
	// both have permission and create access
	if actualUser.ID == resultUser.ID && !(actualUser.AllowView && actualUser.AllowCreate) {
		s.zapLog.Error("User cannot update his/her own allowances if he/she do not have both create and permission access.")
		return &proto.Response{}, err
	}

	if err := s.repository.UpdateAllowances(ctx, resultUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not update with err  %v", err))
		return &proto.Response{}, err
	}

	// return result
	res := &proto.Response{}
	resultUser.Password = ""
	res.User = repository.UnmarshalUser(resultUser)

	return res, nil

}

// UpdatePassword - updates password given a token. The token is used to vaidate and find the user
// A user can only update his/her own password
func (s *Handler) UpdatePassword(ctx context.Context, req *proto.UpdatePasswordRequest) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	// the root user cannot be updated
	if actualUser.Admin {
		s.zapLog.Error("Tried to update root user")
		return &proto.Response{}, errors.New("Root user is not updateable")
	}

	// validate that the user remembers his/her old password
	if err := bcrypt.CompareHashAndPassword([]byte(actualUser.Password), []byte(req.OldPassword)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not compare hash with err  %v", err))
		return &proto.Response{}, err
	}

	// validate password
	resultUser := &repository.User{
		Password: req.NewPassword,
	}

	if err := resultUser.Validate("password"); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate user password with err %v", err))
		return &proto.Response{}, err
	}

	// hash the password
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not generate hash with err %v", err))
		return &proto.Response{}, err
	}

	resultUser.Password = string(hashedPass)

	// give user the id from the toke
	resultUser.ID = actualUser.ID

	if err := s.repository.UpdatePassword(ctx, resultUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not update password with err %v", err))
		return &proto.Response{}, err
	}

	// return result
	res := &proto.Response{}
	resultUser.Password = ""
	res.User = repository.UnmarshalUser(resultUser)

	return res, nil
}

// UpdateBlockUser - can either block a user or unblock a user
// block = true, not blocked = false.
func (s *Handler) UpdateBlockUser(ctx context.Context, req *proto.User) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	// validate that user actually exists & that reqUser is no admin
	reqUser, err := s.repository.Get(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get reqUser with err  %v", err))
		return &proto.Response{}, err
	}

	// the root user cannot be updated
	if reqUser.Admin {
		s.zapLog.Error("Tried to update root user")
		return &proto.Response{}, errors.New("Root user is not updateable")
	}

	// check allowances
	if !actualUser.AllowBlock {
		s.zapLog.Error("User is not allowed to block or unblock other users")
		return &proto.Response{}, errors.New("User is not allowed to block or unblock other users")
	}

	if err := s.repository.UpdateBlockUser(ctx, repository.MarshalUser(req)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Unable to block user with err %v", err))
		return &proto.Response{}, err
	}

	res := &proto.Response{}
	res.User = req

	return res, nil
}

// UploadImage - gets an image from a user and uploads it to s3 store
func (s *Handler) UploadImage(stream proto.UserService_UploadImageServer) error {
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

	authUser, err := s.validateTokenHelper(ctx)
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

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return errors.New("The user is blocked")
	}

	// the root user cannot be updated
	if actualUser.Admin {
		s.zapLog.Error("Tried to update root user")
		return errors.New("Root user is not updateable")
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

	res := &proto.UploadImageResponse{
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
func (s *Handler) Delete(ctx context.Context, req *proto.User) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	if actualUser.AllowDelete != true {
		s.zapLog.Error("User not allowed to delete other users")
		return &proto.Response{}, errors.New("User not allowed to delete other users")
	}

	deleteUser, err := s.repository.Get(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get deleteUser with err  %v", err))
		return &proto.Response{}, err
	}

	// the root user cannot be deleted
	if deleteUser.Admin {
		s.zapLog.Error("Tried to delete root user")
		return &proto.Response{}, errors.New("Root user is not deletable")
	}

	// Delete the user
	if err := s.repository.Delete(ctx, deleteUser); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete user from repository with err %v", err))
		return &proto.Response{}, err
	}

	// also delete users auth history
	if err := s.tokenService.DeleteUserAuthHistory(ctx, req); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete users auth history from crypto with err %v", err))
	}

	// same with token history
	if err := s.tokenService.DeleteUserTokenHistory(ctx, req); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete users auth history from crypto with err %v", err))
	}

	// delete users profile image todo: add this to storage insted... should not be part of handler
	// if the user didn't update profile image
	if strings.Contains(deleteUser.Image, "shared") {
		return &proto.Response{}, nil
	}

	if err := s.storage.Delete(deleteUser.Image); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete user image from storage with err %v", err))
		return &proto.Response{}, err
	}

	if err := s.storage.Delete("hqs/users/" + deleteUser.ID + "/profileImage"); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete image folder from storage with err %v", err))
		return &proto.Response{}, err
	}

	if err := s.storage.Delete("hqs/users/" + deleteUser.ID); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not delete user folder from storage with err %v", err))
		return &proto.Response{}, err
	}

	return &proto.Response{}, nil
}

// Auth - authenticates a user, given that users email and password. Returns a token
func (s *Handler) Auth(ctx context.Context, req *proto.User) (*proto.Token, error) {
	s.zapLog.Info("Recieved new request")

	user, err := s.repository.GetByEmail(ctx, repository.MarshalUser(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Token{}, err
	}

	// check if the user is blocked
	if user.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Token{}, errors.New("The user is blocked")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not compare hash with err  %v", err))
		return &proto.Token{}, err
	}

	token, err := s.tokenService.Encode(context.Background(), repository.UnmarshalUser(user))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not encode user with err  %v", err))
		return &proto.Token{}, err
	}

	// todo: change longiture and lattitude
	if err = s.tokenService.AddAuthToHistory(ctx, repository.UnmarshalUser(user), token, true); err != nil {
		s.zapLog.Warn(fmt.Sprintf("Could not add to auth history with err : %v", err))
	}

	// return result
	res := &proto.Token{}
	res.Token = token

	return res, nil
}

// BlockToken - block token so it cannot be used anymore. Can be undone the next hour
func (s *Handler) BlockToken(ctx context.Context, req *proto.Token) (*proto.Token, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Token{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Token{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Token{}, errors.New("The user is blocked")
	}

	claims, err := s.tokenService.Decode(context.Background(), req.Token)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not decode token with err  %v", err))
		return &proto.Token{}, err
	}

	if claims.User.Id != actualUser.ID {
		s.zapLog.Error("Token user does not match auth user")
		return &proto.Token{}, errors.New("Token user does not match auth user")
	}

	if err := s.tokenService.BlockToken(context.Background(), claims.ID); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not block token with err  %v", err))
		return &proto.Token{}, err
	}

	// return result
	res := &proto.Token{}
	res.Valid = false
	return res, nil
}

// BlockTokenByID - block token so it cannot be used anymore
func (s *Handler) BlockTokenByID(ctx context.Context, req *proto.BlockTokenRequest) (*proto.Token, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Token{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Token{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Token{}, errors.New("The user is blocked")
	}

	// check if the user has rights to the token
	authHistory, err := s.tokenService.GetAuthHistory(context.Background(), repository.UnmarshalUser(actualUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get auth history with err  %v", err))
		return &proto.Token{}, err
	}

	allowed := false
	for _, auth := range authHistory {
		if auth.TokenID == req.TokenID {
			allowed = true
			break
		}
	}

	if !allowed {
		s.zapLog.Error("Token not present or user not allowed to block it")
		return &proto.Token{}, errors.New("Token not present or user not allowed to block it")
	}

	if err := s.tokenService.BlockToken(context.Background(), req.TokenID); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not block token with err  %v", err))
		return &proto.Token{}, err
	}

	// return result
	res := &proto.Token{}
	res.Valid = false
	return res, nil
}

// BlockUsersTokens - block all users token
func (s *Handler) BlockUsersTokens(ctx context.Context, req *proto.Request) (*proto.Response, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.Response{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.Response{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.Response{}, errors.New("The user is blocked")
	}

	if err := s.tokenService.BlockAllUserToken(context.Background(), actualUser.ID); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not block all users tokens with err  %v", err))
		return &proto.Response{}, err
	}

	// return result
	res := &proto.Response{}
	res.Success = true
	return res, nil
}

// GetAuthHistory - returns the last 24 hour auth history of a user
func (s *Handler) GetAuthHistory(ctx context.Context, req *proto.Request) (*proto.AuthHistory, error) {
	s.zapLog.Info("Recieved new request")

	authUser, err := s.validateTokenHelper(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate token with err %v", err))
		return &proto.AuthHistory{}, err
	}

	// validate that user actually exists
	actualUser, err := s.repository.Get(ctx, repository.MarshalUser(authUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get authUser with err  %v", err))
		return &proto.AuthHistory{}, err
	}

	// check if the user is blocked
	if actualUser.Blocked {
		s.zapLog.Error("The user is blocked")
		return &proto.AuthHistory{}, errors.New("The user is blocked")
	}

	// get token history
	authHistory, err := s.tokenService.GetAuthHistory(context.Background(), repository.UnmarshalUser(actualUser))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get auth history with err  %v", err))
		return &proto.AuthHistory{}, err
	}

	// return result
	res := &proto.AuthHistory{}
	res.AuthHistory = authHistory
	return res, nil
}

// ValidateToken - validates a users token
func (s *Handler) ValidateToken(ctx context.Context, req *proto.Token) (*proto.Token, error) {
	s.zapLog.Info("Recieved new request")

	claims, err := s.tokenService.Decode(context.Background(), req.Token)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not decode token with err  %v", err))
		return &proto.Token{}, err
	}

	if claims.User.Id == "" {
		s.zapLog.Error("Invalid user")
		return &proto.Token{}, errors.New("Invalid user")
	}

	// return result
	res := &proto.Token{}
	res.Valid = true
	return res, nil
}

// validateTokenHelper - helper function to validate tokens inside functions in Handler
func (s *Handler) validateTokenHelper(ctx context.Context) (*proto.User, error) {
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

	claims, err := s.tokenService.Decode(context.Background(), token[0])
	if err != nil {
		return nil, err
	}

	if claims.User.Id == "" {
		s.zapLog.Error("Invalid user")
		return nil, errors.New("Invalid user")
	}

	return claims.User, nil
}
