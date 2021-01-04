package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	database "github.com/softcorp-io/hqs-user-service/database"
	handler "github.com/softcorp-io/hqs-user-service/handler"
	repository "github.com/softcorp-io/hqs-user-service/repository"
	service "github.com/softcorp-io/hqs-user-service/service"
	spaces "github.com/softcorp-io/hqs-user-service/spaces"
	storage "github.com/softcorp-io/hqs-user-service/storage"
	emailProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_email_service"
	userProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

type collectionEnv struct {
	userCollection  string
	authCollection  string
	tokenCollection string
}

// Init - initialize .env variables.
func Init(zapLog *zap.Logger) {
	if err := godotenv.Load("hqs.env"); err != nil {
		zapLog.Error(fmt.Sprintf("Could not load hqs.env with err %v", err))
	}
}

func loadCollections() (collectionEnv, error) {
	userCollection, ok := os.LookupEnv("MONGO_DB_USER_COLLECTION")
	if !ok {
		return collectionEnv{}, errors.New("Required MONGO_DB_USER_COLLECTION")
	}
	authCollection, ok := os.LookupEnv("MONGO_DB_AUTH_COLLECTION")
	if !ok {
		return collectionEnv{}, errors.New("Required MONGO_DB_AUTH_COLLECTION")
	}
	tokenCollection, ok := os.LookupEnv("MONGO_DB_TOKEN_COLLECTION")
	if !ok {
		return collectionEnv{}, errors.New("Required MONGO_DB_TOKEN_COLLECTION")
	}
	return collectionEnv{userCollection, authCollection, tokenCollection}, nil
}

// Run - runs a go microservice. Uses zap for logging and a waitGroup for async testing.
func Run(zapLog *zap.Logger, wg *sync.WaitGroup) {
	// creates a database connection and closes it when done
	mongoenv, err := database.GetMongoEnv()
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not set up mongo env with err %v", err))
	}
	// build uri for mongodb
	mongouri := fmt.Sprintf("mongodb+srv://%s:%s@%s/%s?retryWrites=true&w=majority", mongoenv.User, mongoenv.Password, mongoenv.Host, mongoenv.DBname)

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	mongo, err := database.NewMongoDatabase(ctx, zapLog, mongouri)
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not make connection to DB with err %v", err))
	}

	defer mongo.Disconnect(context.Background())

	database := mongo.Database(mongoenv.DBname)

	collections, err := loadCollections()
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not load collections with err: %v", err))
	}

	userCollection := database.Collection(collections.userCollection)

	// setting up data storage
	spacesEnv, err := spaces.GetEnv()
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not set up spaces env with err %v", err))
	}
	spc, err := spaces.GetS3Client(spacesEnv.Key, spacesEnv.Secret, spacesEnv.Region, spacesEnv.Endpoint)
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not set up storage with err %v", err))
	}

	// setup repository
	repo := repository.NewRepository(userCollection)
	if err := createRoot(zapLog, repo); err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not setup root user with err %v", err))

	}

	// setup tokenservice
	authCollection := database.Collection(collections.authCollection)
	tokenCollection := database.Collection(collections.tokenCollection)
	tokenService, err := service.NewTokenService(authCollection, tokenCollection, zapLog)
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not start token service with err %v", err))
	}

	// setup storage
	stor := storage.NewSpaceStorage(spc)

	// setup email client
	emailServiceIP, ok := os.LookupEnv("EMAIL_SERVICE_IP")
	if !ok {
		zapLog.Fatal("Could not get email service ip")
	}
	emailServicePort, ok := os.LookupEnv("EMAIL_SERVICE_PORT")
	if !ok {
		zapLog.Fatal("Could not get email service port")
	}
	conn, err := grpc.DialContext(context.Background(), emailServiceIP+":"+emailServicePort, grpc.WithInsecure())
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not dial email service with err %v", err))
	}
	defer conn.Close()
	emailClient := emailProto.NewEmailServiceClient(conn)
	_, err = emailClient.Ping(context.Background(), &emailProto.Request{})
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not ping email service with err %v", err))
	}

	// use above to create handler
	handle := handler.NewHandler(repo, stor, tokenService, emailClient, zapLog)

	// create the service and run the service
	port, ok := os.LookupEnv("SERVICE_PORT")
	if !ok {
		zapLog.Fatal("Could not get service port")
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Failed to listen with err %v", err))
	}
	defer lis.Close()

	zapLog.Info(fmt.Sprintf("Service running on port: %s", port))

	// setup grpc
	grpcServer := grpc.NewServer()

	// register handler
	userProto.RegisterUserServiceServer(grpcServer, handle)

	// run the server
	if err := grpcServer.Serve(lis); err != nil {
		zapLog.Fatal(fmt.Sprintf("Failed to serve with err %v", err))
	}
}

func createRoot(zapLog *zap.Logger, repo *repository.MongoRepository) error {
	ctx := context.Background()
	if err := repo.GetRoot(ctx); err == nil {
		zapLog.Info("A root user already exist")
		return nil
	}

	rootPassword := generateRandomPassword()
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(rootPassword), bcrypt.DefaultCost)
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not hash root user with err %v", err))
		return err
	}
	rootEmail := "root@softcorp.io"
	rootUser := &repository.User{
		Name:               "Root User",
		Email:              rootEmail,
		Phone:              "00000000",
		CountryCode:        "DK",
		DialCode:           "+45",
		Description:        "This is a special root user.",
		Gender:             false,
		Password:           string(hashedPass),
		AllowView:          true,
		AllowCreate:        true,
		AllowPermission:    true,
		AllowDelete:        true,
		AllowBlock:         true,
		AllowResetPassword: true,
		Admin:              true,
	}
	if err := repo.CreateRoot(ctx, rootUser); err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not create root user with err %v", err))
		return err
	}
	zapLog.Info(fmt.Sprintf("Root user created with info:\n	Email: %s\n	Password: %s", rootEmail, rootPassword))
	return nil
}

func generateRandomPassword() string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ" +
		"abcdefghijklmnopqrstuvwxyzåäö" +
		"0123456789")
	length := 22
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	str := b.String()
	return str
}
