package storage

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
)

// Storage - interface defining functions we can do on upload.
type Storage interface {
	Upload(data bytes.Buffer, path string, allowedTypes ...string) error
	Get(path string, duration time.Duration) (string, error)
	Delete(path string) error
}

// SpaceStorage - the reference we need to act on.
type SpaceStorage struct {
	spc *s3.S3
}

// NewSpaceStorage - returns pointer to DigitalOcean spaces storage.
func NewSpaceStorage(spc *s3.S3) *SpaceStorage {
	return &SpaceStorage{spc}
}

// Upload - uploads a file to storage.
func (s *SpaceStorage) Upload(data bytes.Buffer, filePath string, allowedTypes ...string) error {
	contentType := http.DetectContentType(data.Bytes())
	fmt.Println("recieved content type!", contentType)

	isAllowed := false
	for _, allowedType := range allowedTypes {
		if strings.ToLower(allowedType) == strings.ToLower(contentType) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return errors.New("illegal file type")
	}

	// create a temporary file which we delete when we're done
	tmpFilePath, err := os.Getwd()
	if err != nil {
		return err
	}
	tmpFilePath += "/tmp/profileImage.png"
	// print the directory
	log.Printf("The path to te tmp directory is: %s", tmpFilePath)
	file, err := os.Create(tmpFilePath)
	defer os.Remove(tmpFilePath)
	if err != nil {
		return err
	}
	defer file.Close()
	file.Write(data.Bytes())

	// find uploadfile
	uploadFile, err := os.Open(tmpFilePath)
	if err != nil {
		return err
	}
	defer uploadFile.Close()

	object := s3.PutObjectInput{
		Bucket: aws.String("hqs-spaces"),
		Key:    aws.String(filePath),
		Body:   uploadFile,
		ACL:    aws.String("private"),
	}

	_, err = s.spc.PutObject(&object)
	if err != nil {
		return err
	}

	return nil
}

// Get - gets a url for the file and signs it to be valid for the next amout of time.
func (s *SpaceStorage) Get(filePath string, time time.Duration) (string, error) {
	req, _ := s.spc.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String("hqs-spaces"),
		Key:    aws.String(filePath),
	})
	uploadURL, err := req.Presign(time)
	if err != nil {
		return "", err
	}
	return uploadURL, nil
}

// Delete - deletes upload by path.
func (s *SpaceStorage) Delete(path string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String("hqs-spaces"),
		Key:    aws.String(path),
	}
	_, err := s.spc.DeleteObject(input)
	if err != nil {
		return err
	}
	return nil
}
