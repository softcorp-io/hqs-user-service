package mock

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	database "github.com/softcorp-io/hqs-user-service/database"
)

// stub database
var mongoUserCollection *mongo.Collection
var mongoTokenCollection *mongo.Collection
var mongoAuthCollection *mongo.Collection
var mongoDatabase *mongo.Database

// docker container info
var mongoPool *dockertest.Pool
var mongoResource *dockertest.Resource

// docker database info
var (
	mongoUser      = "mongo"
	mongoPassword  = "secret"
	mongoDBName    = "hqs-user"
	mongoHost      = "localhost"
	mongoPort      = ""
	mongoContainer = "dockermongo"
)

// SetupDockerPostgres - start a docker container running postgres for testing.
func SetupDockerPostgres() error {
	zapLog, _ := zap.NewProduction()

	pool, err := dockertest.NewPool("")
	if err != nil {
		return err
	}

	// get random free port
	for {
		ln, err := net.Listen("tcp", ":"+"0")
		if err == nil {
			mongoPort = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
			mongoContainer = mongoContainer + mongoPort
			ln.Close()
			break
		}
		ln.Close()
	}

	// set global pool
	mongoPool = pool

	if err := TearDownMongoDocker(); err != nil {
		zapLog.Fatal("Could not tear down docker")
	}

	opts := dockertest.RunOptions{
		Repository:   "mongo",
		Tag:          "latest",
		Name:         mongoContainer,
		ExposedPorts: []string{"27017"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"27017": {
				{HostIP: "0.0.0.0", HostPort: mongoPort},
			},
		},
	}

	resource, err := pool.RunWithOptions(&opts)

	if err != nil {
		_ = TearDownMongoDocker()
		return err
	}

	// save values in global variables
	mongoResource = resource

	if err = pool.Retry(func() error {
		// implictly testing database
		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		mongouri := "mongodb://localhost:" + mongoPort
		client, err := database.NewMongoDatabase(ctx, zapLog, mongouri)
		// set global database
		mongoDatabase = client.Database("hqs-user")
		mongoUserCollection = client.Database("hqs-user").Collection("users")
		mongoTokenCollection = client.Database("hqs-user").Collection("auth_history")
		mongoAuthCollection = client.Database("hqs-user").Collection("token_history")
		return err
	}); err != nil {
		_ = TearDownMongoDocker()
		return err
	}

	return nil
}

// TearDownMongoDocker - destorys the docker container.
func TearDownMongoDocker() error {
	mongoPool.RemoveContainerByName(mongoContainer)
	if mongoResource != nil {
		if err := mongoPool.Purge(mongoResource); err != nil {
			return err
		}
	}
	return nil
}

// TruncateUsers - removes all users from 'users' table in database.
func TruncateUsers() {
	if err := mongoUserCollection.Drop(context.Background()); err != nil {
		log.Fatal("Could not delete user collection")
	}
	if err := mongoTokenCollection.Drop(context.Background()); err != nil {
		log.Fatal("Could not delete token collection")
	}
	if err := mongoAuthCollection.Drop(context.Background()); err != nil {
		log.Fatal("Could not delete auth collection")
	}
}

func getMongoUserCollection() *mongo.Collection {
	return mongoUserCollection
}

func getMongoTokenCollection() *mongo.Collection {
	return mongoUserCollection
}

func getMongoAuthCollection() *mongo.Collection {
	return mongoUserCollection
}
