package storage

import (
	"context"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/rs/zerolog/log"
)

type StorageService interface {
	GetS3Client(ctx context.Context, region string) (*s3.Client, error)
	DeleteObject(ctx context.Context, client *s3.Client, bucket string, key string) error
	UploadObject(ctx context.Context, client *s3.Client, bucket string, key string, body io.Reader, contentType string) (UploadResponse, error)
}

type StorageServiceImpl struct {
}

func NewStorageService() StorageService {
	return &StorageServiceImpl{}
}

func (s *StorageServiceImpl) GetS3Client(ctx context.Context, region string) (*s3.Client, error) {
	// https://github.com/aws/aws-sdk-go-v2/issues/1382#issuecomment-1058516508
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)
	if err != nil {
		log.Error().Err(err).Msg("error loading config")
		return nil, exception.ErrCannotCreateUser
	}

	client := s3.NewFromConfig(cfg)
	return client, nil
}

func (s *StorageServiceImpl) DeleteObject(ctx context.Context, client *s3.Client, bucket string, key string) error {
	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	return err
}

func (s *StorageServiceImpl) UploadObject(ctx context.Context, client *s3.Client, bucket string, key string, body io.Reader, contentType string) (UploadResponse, error) {
	uploader := manager.NewUploader(client)
	input := &s3.PutObjectInput{
		Bucket:            aws.String(bucket),
		Key:               aws.String(key),
		Body:              body,
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		// TODO
		// ContentDisposition: aws.String("inline"),
		ContentType: aws.String(contentType),
	}
	output, err := uploader.Upload(ctx, input)
	if err != nil {
		return UploadResponse{}, err
	}

	return UploadResponse{
		ID:  *output.Key,
		URL: output.Location,
	}, nil
}
