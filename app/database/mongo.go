package database

import (
	"context"
	"errors"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// MongoEnv - mongo environment variables.
type MongoEnv struct {
	Host     string
	User     string
	Password string
	DBname   string
}

// GetMongoEnv - returns the environment of mongodb.
func GetMongoEnv() (*MongoEnv, error) {
	host, check := os.LookupEnv("MONGO_HOST")
	if !check {
		return nil, errors.New("Required MONGO_HOST")
	}
	user, check := os.LookupEnv("MONGO_USER")
	if !check {
		return nil, errors.New("Required MONGO_USER")
	}
	dbname, check := os.LookupEnv("MONGO_DBNAME")
	if !check {
		return nil, errors.New("Required MONGO_PASSWORD")
	}
	password, check := os.LookupEnv("MONGO_PASSWORD")
	if !check {
		return nil, errors.New("Required MONGO_PASSWORD")
	}
	return &MongoEnv{host, user, password, dbname}, nil
}

// NewMongoDatabase - creates a connection to a mongo database.
func NewMongoDatabase(ctx context.Context, zapLog *zap.Logger, uri string) (*mongo.Client, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
		uri,
	))
	if err != nil {
		zapLog.Error(fmt.Sprintf("Could not connect to mongo with uri %s", uri))
		return nil, err
	}

	if err := client.Ping(context.Background(), nil); err != nil {
		zapLog.Error(fmt.Sprintf("Could not ping client with err %v", err))
		return nil, err
	}

	/* 	collection := client.Database("hqs-user").Collection("users")

	// create a model for the collection that don't allow duplicate emails
		model := mongo.IndexModel{
	   		Keys:    bsonx.Doc{{"email", bsonx.String("text")}},
	   		Options: options.Index().SetUnique(true),
	   	}
	   	index, err := collection.Indexes().CreateOne(ctx, model)
	   	if err != nil {
	   		zapLog.Error(fmt.Sprintf("Could not create index with err %v", err))
	   		return nil, err
	   	}

	   	zapLog.Info(fmt.Sprintf("Index successfully created with index: %v", index)) */

	return client, err
}
