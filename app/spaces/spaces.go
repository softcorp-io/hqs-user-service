package spaces

import (
	"errors"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// Env defines how ot setup the spaces storage.
type Env struct {
	Key      string
	Secret   string
	Region   string
	Endpoint string
}

// GetEnv - returns the environment used to setting up spaces.
func GetEnv() (*Env, error) {
	key, check := os.LookupEnv("SPACES_KEY")
	if !check {
		return nil, errors.New("Required Spaces Key")
	}
	secret, check := os.LookupEnv("SPACES_SECRET")
	if !check {
		return nil, errors.New("Required Spaces Secret")
	}
	region, check := os.LookupEnv("SPACES_REGION")
	if !check {
		return nil, errors.New("Required Spaces Region")
	}
	endpoint, check := os.LookupEnv("SPACES_ENDPOINT")
	if !check {
		return nil, errors.New("Required Spaces Endpoint")
	}
	return &Env{key, secret, region, endpoint}, nil
}

// GetS3Client - returns the spaces client.
func GetS3Client(key string, secret string, region string, endpoint string) (*s3.S3, error) {
	s3Config := &aws.Config{
		Credentials: credentials.NewStaticCredentials(key, secret, ""),
		Endpoint:    aws.String(endpoint),
		Region:      aws.String(region),
	}
	newSession := session.New(s3Config)
	s3Client := s3.New(newSession)
	return s3Client, nil
}
