package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
	"google.golang.org/grpc/metadata"
)

// Create - creates a user.
func Create(cl proto.UserServiceClient, name string, email string, phone string, password string, viewAccess bool, createAccess bool, permissionAccess bool, deleteAccess bool, token string, wg *sync.WaitGroup) (*proto.User, error) {
	defer wg.Done()
	// build context
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	userResponse, err := cl.Create(ctx, &proto.User{
		Name:            name,
		Email:           email,
		Phone:           phone,
		Password:        password,
		AllowView:       viewAccess,
		AllowCreate:     createAccess,
		AllowPermission: permissionAccess,
		AllowDelete:     deleteAccess,
	})
	if err != nil {
		return &proto.User{}, err
	}
	return userResponse.User, nil
}

// GenerateSignupToken - creates a signuptoken.
func GenerateSignupToken(cl proto.UserServiceClient, viewAccess bool, createAccess bool, permissionAccess bool, deleteAccess bool, token string, wg *sync.WaitGroup) (string, error) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	tokenResponse, err := cl.GenerateSignupToken(ctx, &proto.User{
		AllowView:       viewAccess,
		AllowCreate:     createAccess,
		AllowPermission: permissionAccess,
		AllowDelete:     deleteAccess,
	})
	if err != nil {
		return "", err
	}
	return tokenResponse.Token, nil
}

// Signup - creates a user from a token and info.
func Signup(cl proto.UserServiceClient, name string, email string, phone string, password string, token string, wg *sync.WaitGroup) error {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err := cl.Signup(ctx, &proto.User{
		Name:     name,
		Email:    email,
		Phone:    phone,
		Password: password,
	})
	if err != nil {
		return err
	}
	return nil
}

// Get - get a user by its id.
func Get(cl proto.UserServiceClient, id string, token string, wg *sync.WaitGroup) (*proto.User, error) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	userResponse, err := cl.Get(ctx, &proto.User{
		Id: id,
	})
	if err != nil {
		return &proto.User{}, err
	}
	return userResponse.User, nil
}

// GetByEmail - get a user by its email.
func GetByEmail(cl proto.UserServiceClient, email string, token string, wg *sync.WaitGroup) (*proto.User, error) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	userResponse, err := cl.GetByEmail(ctx, &proto.User{
		Email: email,
	})
	if err != nil {
		return &proto.User{}, err
	}
	return userResponse.User, nil
}

// GetByToken - get a user by its token.
func GetByToken(cl proto.UserServiceClient, token string, wg *sync.WaitGroup) (*proto.User, error) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	userResponse, err := cl.GetByToken(ctx, &proto.Request{})
	if err != nil {
		return &proto.User{}, err
	}
	return userResponse.User, nil
}

// GetAll - get a user by its token.
func GetAll(cl proto.UserServiceClient, token string, wg *sync.WaitGroup) ([]*proto.User, error) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	userResponse, err := cl.GetAll(ctx, &proto.Request{})
	if err != nil {
		return []*proto.User{}, err
	}
	return userResponse.Users, nil
}

// UpdateProfile - updates a users profile. Finds him/her by the token.
func UpdateProfile(cl proto.UserServiceClient, name string, email string, phone string, token string, wg *sync.WaitGroup) error {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err := cl.UpdateProfile(ctx, &proto.User{
		Name:  name,
		Email: email,
		Phone: phone,
	})
	if err != nil {
		return err
	}
	return nil
}

// UpdateAllowances - updates a users allowances.
func UpdateAllowances(cl proto.UserServiceClient, id string, viewAccess bool, createAccess bool, permissionAccess bool, deleteAccess bool, token string, wg *sync.WaitGroup) error {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err := cl.UpdateAllowances(ctx, &proto.User{
		Id:              id,
		AllowView:       viewAccess,
		AllowCreate:     createAccess,
		AllowPermission: permissionAccess,
		AllowDelete:     deleteAccess,
	})
	if err != nil {
		return err
	}
	return nil
}

// UpdatePassword - updates the password given an old & new password and the token
// to find the user.
func UpdatePassword(cl proto.UserServiceClient, old string, new string, token string, wg *sync.WaitGroup) error {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err := cl.UpdatePassword(ctx, &proto.UpdatePasswordRequest{
		OldPassword: old,
		NewPassword: new,
	})
	if err != nil {
		return err
	}
	return nil
}

// UploadImage - uploads image to server.
func UploadImage(cl proto.UserServiceClient, imagepath string, token string, wg *sync.WaitGroup) error {
	defer wg.Done()
	file, err := os.Open(imagepath)
	if err != nil {
		return err
	}
	defer file.Close()

	ctx := context.Background()

	stream, err := cl.UploadImage(ctx)
	if err != nil {
		return err
	}

	req := &proto.UploadImageRequest{
		Data: &proto.UploadImageRequest_Token{
			Token: token,
		},
	}
	if err := stream.Send(req); err != nil {
		log.Fatal("cannot authenticate... ", err)
	}

	reader := bufio.NewReader(file)
	buffer := make([]byte, 1024)

	for {
		n, err := reader.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println("cannot read chunk to buffer: ", err)
			return err
		}
		req := &proto.UploadImageRequest{
			Data: &proto.UploadImageRequest_ChunkData{
				ChunkData: buffer[:n],
			},
		}

		err = stream.Send(req)
		if err != nil {
			log.Println("cannot send chunk to server: ", err, stream.RecvMsg(nil))
			return err
		}
	}

	req = &proto.UploadImageRequest{
		Data: &proto.UploadImageRequest_Close{
			Close: true,
		},
	}

	if err := stream.Send(req); err != nil {
		return err
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		log.Println("could not close stream")
		return err
	}
	fmt.Println(resp.Size)

	return nil
}

// Auth - authenticates a user and returns a string and an error.
func Auth(cl proto.UserServiceClient, email string, password string, wg *sync.WaitGroup) (string, error) {
	defer wg.Done()
	crypto, err := cl.Auth(context.Background(), &proto.User{
		Email:    email,
		Password: password,
	})
	if err != nil {
		return "", err
	}
	return crypto.Token, nil
}

// Delete - deletes user given id.
func Delete(cl proto.UserServiceClient, id string, token string, wg *sync.WaitGroup) error {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err := cl.Delete(ctx, &proto.User{
		Id: id,
	})
	if err != nil {
		return err
	}
	return nil
}

// ValidateToken - validates a users token.
func ValidateToken(cl proto.UserServiceClient, token string, wg *sync.WaitGroup) error {
	defer wg.Done()
	_, err := cl.ValidateToken(context.Background(), &proto.Token{
		Token: token,
	})
	if err != nil {
		return err
	}
	return nil
}

// BlockToken - blocks a token in the redis store
func BlockToken(cl proto.UserServiceClient, usertoken string, blocktoken string, wg *sync.WaitGroup) error {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": usertoken})
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err := cl.BlockToken(ctx, &proto.Token{
		Token: blocktoken,
	})
	if err != nil {
		return err
	}
	return nil
}

// BlockTokenByID - blocks a token in the redis store
func BlockTokenByID(cl proto.UserServiceClient, usertoken string, blocktoken string, wg *sync.WaitGroup) error {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": usertoken})
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err := cl.BlockTokenByID(ctx, &proto.BlockTokenRequest{
		TokenID: blocktoken,
	})
	if err != nil {
		return err
	}
	return nil
}

// GetAuthHistory - returns users auth history.
func GetAuthHistory(cl proto.UserServiceClient, token string, wg *sync.WaitGroup) (*proto.AuthHistory, error) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	md := metadata.New(map[string]string{"token": token})
	ctx = metadata.NewOutgoingContext(ctx, md)

	authHistory, err := cl.GetAuthHistory(ctx, &proto.Request{})
	if err != nil {
		return nil, err
	}
	return authHistory, nil
}
