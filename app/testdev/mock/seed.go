package mock

import (
	"context"
	"log"
	"time"

	repository "github.com/softcorp-io/hqs-user-service/repository"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Seed - Seeds one user to the database.
func Seed(name string, email string, phone string, password string, allowView bool, allowCreate bool, allowPermission bool, allowDelete bool, allowBlock bool, allowReset bool, blocked bool, gender bool) string {
	hasshedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		_ = TearDownMongoDocker()
		log.Fatalf("Error hashing password, err: %v. \n", err)
	}

	password = string(hasshedPassword)

	id := uuid.NewV4().String()

	user := &repository.User{
		ID:              id,
		Name:            name,
		Email:           email,
		Phone:           phone,
		CountryCode:     "DK",
		DialCode:        "+45",
		Image:           "some image",
		Gender:          gender,
		Description:     "some description",
		Password:        password,
		AllowView:       allowView,
		AllowCreate:     allowCreate,
		AllowPermission: allowPermission,
		AllowDelete:     allowDelete,
		AllowBlock:      allowBlock,
		Blocked:         blocked,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Birthday:        time.Now(),
	}

	_, err = mongoUserCollection.InsertOne(context.Background(), user)

	if err != nil {
		_ = TearDownMongoDocker()
		log.Fatal("Could not seed user")
	}

	return id
}
