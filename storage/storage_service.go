package storage

import (
	"context"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	tmtypes "github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/rs/zerolog/log"
)

type PresignedPostRequest struct {
	URL    string            `json:"url"`
	Fields map[string]string `json:"fields"`
}

type StorageService interface {
	GetS3Client(ctx context.Context, region string) (*s3.Client, error)
	DeleteObject(ctx context.Context, client *s3.Client, bucket string, key string) error
	UploadObject(ctx context.Context, client *s3.Client, bucket string, key string, body io.Reader, contentType string) (UploadResponse, error)
	GenerateUploadPresignedURL(ctx context.Context, client *s3.Client, bucket string, key string, lifetimeSecs int64) (*PresignedPostRequest, error)
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
		return nil, err
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
	tm := transfermanager.New(client)
	input := &transfermanager.UploadObjectInput{
		Bucket:            aws.String(bucket),
		Key:               aws.String(key),
		Body:              body,
		ChecksumAlgorithm: tmtypes.ChecksumAlgorithmSha256,
		// ContentDisposition: aws.String("inline"),
		ContentType: aws.String(contentType),
	}
	output, err := tm.UploadObject(ctx, input)
	if err != nil {
		return UploadResponse{}, err
	}

	return UploadResponse{
		ID:  *output.Key,
		URL: *output.Location,
	}, nil
}

func (s *StorageServiceImpl) GenerateUploadPresignedURL(ctx context.Context, client *s3.Client, bucket string, key string, lifetimeSecs int64) (*PresignedPostRequest, error) {
	presignClient := s3.NewPresignClient(client)
	request, err := presignClient.PresignPostObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}, func(options *s3.PresignPostOptions) {
		options.Expires = time.Duration(lifetimeSecs) * time.Second
	})

	if err != nil {
		log.Error().Err(err).Msgf("Couldn't get a presigned post request to put %v:%v", bucket, key)
		return nil, err
	}
	return &PresignedPostRequest{
		URL:    request.URL,
		Fields: request.Values,
	}, nil
}
