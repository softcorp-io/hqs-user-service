package repository

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"
	"unicode"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/badoux/checkmail"
	"github.com/golang/protobuf/ptypes"
	uuid "github.com/satori/go.uuid"
	userProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
)

// User - struct.
type User struct {
	ID                 string    `bson:"id" json:"id"`
	Name               string    `bson:"name" json:"name"`
	Email              string    `bson:"email" json:"email"`
	Phone              string    `bson:"phone" json:"phone"`
	CountryCode        string    `bson:"country_code" json:"country_code"`
	DialCode           string    `bson:"dial_code" json:"dial_code"`
	Gender             bool      `bson:"gender" json:"gender"`
	Image              string    `bson:"image" json:"image"`
	Description        string    `bson:"description" json:"description"`
	Title              string    `bson:"title" json:"title"`
	Birthday           time.Time `bson:"birthday" json:"birthday"`
	Password           string    `bson:"password" json:"password"`
	AllowView          bool      `bson:"allow_view" json:"allow_view"`
	AllowCreate        bool      `bson:"allow_create" json:"allow_create"`
	AllowPermission    bool      `bson:"allow_permission" json:"allow_permission"`
	AllowDelete        bool      `bson:"allow_delete" json:"allow_delete"`
	AllowBlock         bool      `bson:"allow_block" json:"allow_block"`
	AllowResetPassword bool      `bson:"allow_reset_password" json:"allow_reset_password"`
	Blocked            bool      `bson:"blocked" json:"blocked"`
	Admin              bool      `bson:"admin" json:"admin"`
	CreatedAt          time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt          time.Time `bson:"updated_at" json:"updated_at"`
}

// Upload -struct.
type Upload struct {
	Content []byte
}

// Repository - interface.
type Repository interface {
	Create(ctx context.Context, user *User) error
	CreateRoot(ctx context.Context, user *User) error
	Signup(ctx context.Context, user *User) error
	GetAll(ctx context.Context) ([]*User, error)
	Get(ctx context.Context, user *User) (*User, error)
	GetRoot(ctx context.Context) error
	GetByEmail(ctx context.Context, user *User) (*User, error)
	UpdateProfile(ctx context.Context, user *User) error
	UpdateAllowances(ctx context.Context, user *User) error
	UpdateImage(ctx context.Context, user *User) error
	UpdatePassword(ctx context.Context, user *User) error
	UpdateBlockUser(ctx context.Context, user *User) error
	Delete(ctx context.Context, user *User) error
}

// MongoRepository - struct.
type MongoRepository struct {
	mongo *mongo.Collection
}

// NewRepository - returns MongoRepository pointer.
func NewRepository(mongo *mongo.Collection) *MongoRepository {
	return &MongoRepository{mongo}
}

// MarshalUserCollection - marshal collection from userProto.users to users.
func MarshalUserCollection(users []*userProto.User) []*User {
	u := make([]*User, len(users))
	for _, val := range users {
		u = append(u, MarshalUser(val))
	}
	return u
}

// MarshalUser - marshals single user from userProto.user to user.
func MarshalUser(user *userProto.User) *User {
	createdAt, _ := ptypes.Timestamp(user.CreatedAt)
	updatedAt, _ := ptypes.Timestamp(user.UpdatedAt)
	birthday, err := time.Parse("2006-01-02", user.Birthday)
	// if date is not correct, make it time.now()
	if err != nil {
		birthday = time.Now()
	}
	return &User{
		ID:                 user.Id,
		Name:               user.Name,
		Email:              user.Email,
		Phone:              user.Phone,
		CountryCode:        user.CountryCode,
		DialCode:           user.DialCode,
		Gender:             user.Gender,
		Image:              user.Image,
		Description:        user.Description,
		Title:              user.Title,
		Password:           user.Password,
		AllowView:          user.AllowView,
		AllowCreate:        user.AllowCreate,
		AllowPermission:    user.AllowPermission,
		AllowDelete:        user.AllowDelete,
		AllowBlock:         user.AllowBlock,
		AllowResetPassword: user.AllowResetPassword,
		Blocked:            user.Blocked,
		Admin:              user.Admin,
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
		Birthday:           birthday,
	}
}

// UnmarshalUserCollection - unmarshal collection from users to userProto.users.
func UnmarshalUserCollection(users []*User) []*userProto.User {
	u := []*userProto.User{}
	for _, val := range users {
		u = append(u, UnmarshalUser(val))
	}
	return u
}

// UnmarshalUser - marshals single user from user to userProto.user.
func UnmarshalUser(user *User) *userProto.User {
	createdAt, _ := ptypes.TimestampProto(user.CreatedAt)
	updatedAt, _ := ptypes.TimestampProto(user.UpdatedAt)
	birthday := user.Birthday.String()
	return &userProto.User{
		Id:                 user.ID,
		Name:               user.Name,
		Email:              user.Email,
		Phone:              user.Phone,
		CountryCode:        user.CountryCode,
		DialCode:           user.DialCode,
		Gender:             user.Gender,
		Image:              user.Image,
		Description:        user.Description,
		Title:              user.Title,
		Password:           user.Password,
		AllowView:          user.AllowView,
		AllowCreate:        user.AllowCreate,
		AllowPermission:    user.AllowPermission,
		AllowDelete:        user.AllowDelete,
		AllowBlock:         user.AllowBlock,
		AllowResetPassword: user.AllowResetPassword,
		Blocked:            user.Blocked,
		Admin:              user.Admin,
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
		Birthday:           birthday,
	}
}

// passwordValidator - helper func to validate password.
func passwordValidator(s string) bool {
	var (
		hasMinLen = false
		hasUpper  = false
		hasLower  = false
		hasNumber = false
	)
	if len(s) >= 6 {
		hasMinLen = true
	}
	for _, char := range s {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber
}

// ValidateAllowances - validates the allowances of a user.
func (u *User) ValidateAllowances() error {
	// to delete, change permissions or create users, one has to be able to see them
	createNoViewAccess := u.AllowCreate && (!u.AllowView || !u.AllowPermission)
	deleteNoViewAccess := u.AllowDelete && !u.AllowView
	permissionNoViewAccess := u.AllowPermission && !u.AllowView
	blockNoViewAccess := u.AllowBlock && !u.AllowView
	if createNoViewAccess {
		return errors.New("Create access bot allowed without view & permission access")
	}
	if deleteNoViewAccess {
		return errors.New("Delete access not allowed without view access")
	}
	if permissionNoViewAccess {
		return errors.New("Permission access not allowed without view access")
	}
	if blockNoViewAccess {
		return errors.New("Block access not allowed without view access")
	}
	return nil
}

// Validate - validates input.
func (u *User) Validate(action string) error {
	switch strings.ToLower(action) {
	case "create":
		if u.Name == "" {
			return errors.New("Required nickname")
		}
		if u.ID == "" || len(u.ID) < 20 {
			return errors.New("Invalid UUID")
		}
		if err := checkmail.ValidateFormat(u.Email); err != nil {
			return errors.New("Invalid email")
		}
		if !passwordValidator(u.Password) {
			return errors.New("Invalid password")
		}
		if err := u.ValidateAllowances(); err != nil {
			return err
		}
	case "profile":
		if u.Name == "" {
			return errors.New("Required nickname")
		}
		if err := checkmail.ValidateFormat(u.Email); err != nil {
			return errors.New("Invalid email")
		}
	case "password":
		if !passwordValidator(u.Password) {
			return errors.New("Invalid password")
		}
	case "allowance":
		if err := u.ValidateAllowances(); err != nil {
			return err
		}
	}
	return nil
}

// Prepare - prepares input to be injected into the database.
func (u *User) prepare(action string) {
	switch strings.ToLower(action) {
	case "create":
		u.Name = strings.TrimSpace(u.Name)
		u.Email = strings.TrimSpace(u.Email)
		u.Phone = strings.TrimSpace(u.Phone)
		u.CountryCode = strings.TrimSpace(u.CountryCode)
		u.DialCode = strings.TrimSpace(u.DialCode)
		u.Admin = false
		u.CreatedAt = time.Now()
		u.UpdatedAt = time.Now()
		u.Birthday = time.Now()
		if u.Gender {
			u.Image = "hqs/users/shared/profileImage/femaleProfileImage.png"
		} else {
			u.Image = "hqs/users/shared/profileImage/maleProfileImage.png"
		}
	case "update":
		u.Name = strings.TrimSpace(u.Name)
		u.Email = strings.TrimSpace(u.Email)
		u.Phone = strings.TrimSpace(u.Phone)
		u.Admin = false
		u.CountryCode = strings.TrimSpace(u.CountryCode)
		u.DialCode = strings.TrimSpace(u.DialCode)
		u.UpdatedAt = time.Now()
	case "root":
		u.Name = strings.TrimSpace(u.Name)
		u.Email = strings.TrimSpace(u.Email)
		u.Phone = strings.TrimSpace(u.Phone)
		u.CountryCode = strings.TrimSpace(u.CountryCode)
		u.DialCode = strings.TrimSpace(u.DialCode)
		u.CreatedAt = time.Now()
		u.UpdatedAt = time.Now()
		u.Birthday = time.Now()
		if u.Gender {
			u.Image = "hqs/users/shared/profileImage/femaleProfileImage.png"
		} else {
			u.Image = "hqs/users/shared/profileImage/maleProfileImage.png"
		}
	}
}

// Create - creates a new user.
func (r *MongoRepository) Create(ctx context.Context, user *User) error {
	user.ID = uuid.NewV4().String()
	if err := user.Validate("create"); err != nil {
		return err
	}

	user.prepare("create")

	// check that a user don't exist with that email
	checkUser, _ := r.GetByEmail(ctx, user)
	if checkUser != nil {
		return errors.New("A user with that email already exists")
	}

	_, err := r.mongo.InsertOne(ctx, user)
	if err != nil {
		return err
	}

	return err
}

// CreateRoot - creates the root user.
func (r *MongoRepository) CreateRoot(ctx context.Context, user *User) error {
	user.ID = uuid.NewV4().String()
	if err := user.Validate("create"); err != nil {
		return err
	}

	user.prepare("root")

	// check that a user don't exist with that email
	checkUser, _ := r.GetByEmail(ctx, user)
	if checkUser != nil {
		return errors.New("A user with that email already exists")
	}

	_, err := r.mongo.InsertOne(ctx, user)
	if err != nil {
		return err
	}

	return err
}

// Signup - same as create, but a uuid is given.
func (r *MongoRepository) Signup(ctx context.Context, user *User) error {
	if err := user.Validate("create"); err != nil {
		return err
	}

	user.prepare("create")

	// check that a user don't exist with that email
	checkUser, _ := r.GetByEmail(ctx, user)
	if checkUser != nil {
		return errors.New("A user with that email already exists")
	}

	_, err := r.mongo.InsertOne(ctx, user)

	return err
}

// UpdateProfile - updates profile. Only profile, not password.
func (r *MongoRepository) UpdateProfile(ctx context.Context, user *User) error {
	if err := user.Validate("profile"); err != nil {
		return err
	}

	user.prepare("update")

	updateUser := bson.M{
		"$set": bson.M{
			"name":         user.Name,
			"email":        user.Email,
			"phone":        user.Phone,
			"country_code": user.CountryCode,
			"dial_code":    user.DialCode,
			"gender":       user.Gender,
			"description":  user.Description,
			"title":        user.Title,
			"birthday":     user.Birthday,
			"updated_at":   user.UpdatedAt,
		},
	}

	_, err := r.mongo.UpdateOne(
		ctx,
		bson.M{"id": user.ID},
		updateUser,
	)

	if err != nil {
		return err
	}

	return err
}

// UpdateAllowances - updates users allowances / rights to view, create and delete.
func (r *MongoRepository) UpdateAllowances(ctx context.Context, user *User) error {
	if err := user.Validate("allowance"); err != nil {
		return err
	}

	updateUser := bson.M{
		"$set": bson.M{
			"allow_view":           user.AllowView,
			"allow_create":         user.AllowCreate,
			"allow_permission":     user.AllowPermission,
			"allow_delete":         user.AllowDelete,
			"allow_block":          user.AllowBlock,
			"allow_reset_password": user.AllowResetPassword,
			"updated_at":           user.UpdatedAt,
		},
	}

	_, err := r.mongo.UpdateOne(
		ctx,
		bson.M{"id": user.ID},
		updateUser,
	)

	if err != nil {
		return err
	}

	return nil
}

// UpdateImage - updates the path of the image.
func (r *MongoRepository) UpdateImage(ctx context.Context, user *User) error {
	user.prepare("update")

	updateUser := bson.M{
		"$set": bson.M{
			"image":      user.Image,
			"updated_at": user.UpdatedAt,
		},
	}

	_, err := r.mongo.UpdateOne(
		ctx,
		bson.M{"id": user.ID},
		updateUser,
	)

	if err != nil {
		return err
	}

	return nil
}

// UpdatePassword - updates user password.
func (r *MongoRepository) UpdatePassword(ctx context.Context, user *User) error {
	if err := user.Validate("password"); err != nil {
		return err
	}

	user.prepare("update")

	updateUser := bson.M{
		"$set": bson.M{
			"password":   user.Password,
			"updated_at": user.UpdatedAt,
		},
	}

	_, err := r.mongo.UpdateOne(
		ctx,
		bson.M{"id": user.ID},
		updateUser,
	)

	if err != nil {
		return err
	}

	return nil
}

// UpdateBlockUser - update the block status on a user.
func (r *MongoRepository) UpdateBlockUser(ctx context.Context, user *User) error {
	updateUser := bson.M{
		"$set": bson.M{
			"blocked":    user.Blocked,
			"updated_at": user.UpdatedAt,
		},
	}
	_, err := r.mongo.UpdateOne(
		ctx,
		bson.M{"id": user.ID},
		updateUser,
	)
	if err != nil {
		return err
	}

	return nil
}

// Get - finds single user using the users id.
func (r *MongoRepository) Get(ctx context.Context, user *User) (*User, error) {
	userReturn := User{}

	if err := r.mongo.FindOne(ctx, bson.M{"id": user.ID}).Decode(&userReturn); err != nil {
		return nil, err
	}

	return &userReturn, nil
}

// GetRoot - finds the single root user.
func (r *MongoRepository) GetRoot(ctx context.Context) error {
	userReturn := User{}

	if err := r.mongo.FindOne(ctx, bson.M{"admin": true}).Decode(&userReturn); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

// GetByEmail fetches a single user by their email address.
func (r *MongoRepository) GetByEmail(ctx context.Context, user *User) (*User, error) {
	userReturn := User{}

	if err := r.mongo.FindOne(ctx, bson.M{"email": user.Email}).Decode(&userReturn); err != nil {
		return nil, err
	}

	return &userReturn, nil
}

// GetAll - returns every user in the system. Also strips password of each user.
func (r *MongoRepository) GetAll(ctx context.Context) ([]*User, error) {
	usersReturn := []*User{}

	cursor, err := r.mongo.Find(context.TODO(), bson.M{})

	if err != nil {
		return []*User{}, err
	}

	for cursor.Next(ctx) {
		var tempUser User
		cursor.Decode(&tempUser)

		// don't add root user
		if tempUser.Admin {
			continue
		}

		usersReturn = append(usersReturn, &tempUser)
	}

	return usersReturn, nil
}

// Delete - deletes a given user.
func (r *MongoRepository) Delete(ctx context.Context, user *User) error {

	_, err := r.mongo.DeleteOne(ctx, bson.M{"id": user.ID})
	if err != nil {
		return err
	}

	return nil
}
