package profile

import (
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	conf "github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

const (
	TmpDir          = "tmp"
	ValidExtensions = ".jpg,.jpeg,.png,.gif"
	S3Dir           = "profile"
)

type ProfileHandler struct {
	conf.Config
	*validator.Validate
	ProfileService
}

func NewProfileHandler(profileService ProfileService, config conf.Config, validate *validator.Validate) ProfileHandler {
	return ProfileHandler{
		config,
		validate,
		profileService,
	}
}

func (h *ProfileHandler) GetProfile(ctx *gin.Context) {
	u, err := user.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("get profile for user UUID %s", u.Uuid)
	ctx.JSON(http.StatusOK, u)
}

func (h *ProfileHandler) UpdateProfile(ctx *gin.Context) {
	u, err := user.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("update profile for user UUID %s", u.Uuid)
	var req UpdateProfileRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err = h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	userEntity, err := h.UpdateProfileByUserUuid(ctx, u.Uuid, req)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	authenticatedUser := user.ToAuthenticatedUser(userEntity)
	ctx.JSON(http.StatusOK, authenticatedUser)
}

func (h *ProfileHandler) UpdatePassword(ctx *gin.Context) {
	u, err := user.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("update password for user UUID %s", u.Uuid)
	var req UpdatePasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err = h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	userEntity, err := h.UpdatePasswordByUserUuid(ctx, u.Uuid, req)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if err == exception.ErrNotFound || err == exception.ErrInvalidRequest {
			statusCode = http.StatusBadRequest
		}
		ctx.AbortWithStatusJSON(statusCode, exception.ErrorResponse(err, statusCode))
		return
	}

	authenticatedUser := user.ToAuthenticatedUser(userEntity)
	ctx.JSON(http.StatusOK, authenticatedUser)
}

func (h *ProfileHandler) UpdateImage(ctx *gin.Context) {
	u, err := user.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("update image for user UUID %s", u.Uuid)
	file, err := ctx.FormFile("image")
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}
	fmt.Println(file.Filename)
	fmt.Printf("type: %v\n", file.Header.Get("Content-Type"))

	ext, err := getFileExtension(file)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	now := time.Now()
	nowAsString := now.Format("20060102150405")
	filename := u.Uuid.String() + "_" + nowAsString + ext

	tmpFile := TmpDir + "/" + filename
	ctx.SaveUploadedFile(file, tmpFile)

	// Upload to S3
	f, err := file.Open()
	if err != nil {
		log.Error().Err(err).Msg("error opening file")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	// https://github.com/aws/aws-sdk-go-v2/issues/1382#issuecomment-1058516508
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(h.Config.AwsRegion),
	)
	if err != nil {
		log.Error().Err(err).Msg("error loading config")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(client)
	input := &s3.PutObjectInput{
		Bucket:            aws.String(h.Config.AwsS3Bucket),
		Key:               aws.String(S3Dir + "/" + filename),
		Body:              f,
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
	}
	output, err := uploader.Upload(ctx, input)
	if err != nil {
		log.Error().Err(err).Msg("error uploading file")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	fmt.Println(output)

	// TODO
	// if err := os.Remove(tmpFile); err != nil {
	// 	log.Warn().Err(err).Msgf("cannot remove file %s", tmpFile)
	// }
}

func getFileExtension(file *multipart.FileHeader) (string, error) {
	// https://github.com/gabriel-vasile/mimetype
	extensions, err := mime.ExtensionsByType(file.Header.Get("Content-Type"))
	if err != nil {
		return "", err
	}

	v := strings.Split(ValidExtensions, ",")
	isExtensionValid := false
	ext := ""
	for _, e := range extensions {
		if slices.Contains(v, e) {
			isExtensionValid = true
			ext = e
			break
		}
	}

	if !isExtensionValid {
		return "", exception.ErrInvalidFileExtension
	}

	return ext, nil
}

func (h *ProfileHandler) DeleteProfile(ctx *gin.Context) {
	u, err := user.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("delete profile for user UUID %s", u.Uuid)

	userEntity, err := h.DeleteProfileByUserUuid(ctx, u.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	authenticatedUser := user.ToAuthenticatedUser(userEntity)
	ctx.JSON(http.StatusOK, authenticatedUser)
}
