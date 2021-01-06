package testing

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	mock "github.com/softcorp-io/hqs-user-service/testdev/mock"
	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
)

var myClient proto.UserServiceClient

func TestMain(m *testing.M) {
	var wgServer sync.WaitGroup
	wgServer.Add(1)
	go mock.RunServer(&wgServer)
	wgServer.Wait()

	var conn *grpc.ClientConn
	conn, err := grpc.Dial(":9091", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()
	cl := proto.NewUserServiceClient(conn)
	myClient = cl

	code := m.Run()

	mock.TearDownMongoDocker()
	os.Exit(code)
}

func TestUploadImage(t *testing.T) {
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
	tokenResponse, err := myClient.Auth(ctx, &proto.User{
		Email:    seedEmail,
		Password: seedPassword,
	})

	assert.Nil(t, err)
	assert.NotEmpty(t, tokenResponse)

	// arrange
	// 1. get server stream
	stream, err := myClient.UploadImage(ctx)
	assert.Nil(t, err)

	// 2. authenticate
	req := &proto.UploadImageRequest{
		Data: &proto.UploadImageRequest_Token{
			Token: tokenResponse.Token,
		},
	}
	err = stream.Send(req)
	if err != nil {
	}

	// 3. upload file
	file, err := os.Open("invincible.jpg")
	if err != nil {
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	buffer := make([]byte, 1024)

	for {
		n, err := reader.Read(buffer)
		if err == io.EOF {
			break
		}
		assert.Nil(t, err)

		req := &proto.UploadImageRequest{
			Data: &proto.UploadImageRequest_ChunkData{
				ChunkData: buffer[:n],
			},
		}
		err = stream.Send(req)
		assert.Nil(t, err)
	}

	// 5. recieve file size
	resp, err := stream.CloseAndRecv()
	assert.Nil(t, err)
	assert.True(t, resp.Size > 0)
}
