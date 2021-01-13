package mock

import (
	"context"
	"log"
	"time"

	repository "github.com/softcorp-io/hqs-user-service/repository"
	privilegeProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_privilege_service"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Seed - Seeds one user to the database.
func Seed(name string, email string, phone string, password string, viewAllUsers bool, createUser bool, managePrivileges bool, deleteUser bool, blockUser bool, sendResetPasswordEmail bool, blocked bool, gender bool) string {
	hasshedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		_ = TearDownMongoDocker()
		log.Fatalf("Error hashing password, err: %v. \n", err)
	}

	password = string(hasshedPassword)

	id := uuid.NewV4().String()

	privResp, _ := pcMock.Create(context.Background(), &privilegeProto.Privilege{
		Id:                     uuid.NewV4().String(),
		Name:                   "Test",
		ViewAllUsers:           viewAllUsers,
		CreateUser:             createUser,
		ManagePrivileges:       managePrivileges,
		DeleteUser:             deleteUser,
		BlockUser:              blockUser,
		SendResetPasswordEmail: sendResetPasswordEmail,
	})

	user := &repository.User{
		ID:          id,
		Name:        name,
		Email:       email,
		Phone:       phone,
		CountryCode: "DK",
		DialCode:    "+45",
		Image:       "some image",
		Gender:      gender,
		Description: "some description",
		Password:    password,
		PrivilegeID: privResp.Privilege.Id,
		Blocked:     blocked,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Birthday:    time.Now(),
	}

	_, err = mongoUserCollection.InsertOne(context.Background(), user)

	if err != nil {
		_ = TearDownMongoDocker()
		log.Fatal("Could not seed user")
	}

	return id
}
