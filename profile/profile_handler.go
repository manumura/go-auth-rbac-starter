package profile

import (
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	conf "github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/storage"
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
	storage.StorageService
}

func NewProfileHandler(profileService ProfileService, storageService storage.StorageService, config conf.Config, validate *validator.Validate) ProfileHandler {
	return ProfileHandler{
		config,
		validate,
		profileService,
		storageService,
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

	filename, err := getFileName(file, u.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	// tmpFile := TmpDir + "/" + filename
	// ctx.SaveUploadedFile(file, tmpFile)

	f, err := file.Open()
	if err != nil {
		log.Error().Err(err).Msg("error opening file")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	client, err := h.StorageService.GetS3Client(ctx, h.Config.AwsRegion)
	if err != nil {
		log.Error().Err(err).Msg("error loading config")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	// Delete old image
	if u.ImageID != "" {
		err = h.StorageService.DeleteObject(ctx, client, h.Config.AwsS3Bucket, u.ImageID)
		if err != nil {
			log.Error().Err(err).Msg("error deleting old image")
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
			return
		}
	}

	// Upload to S3
	r, err := h.StorageService.UploadObject(ctx, client, h.Config.AwsS3Bucket, S3Dir+"/"+filename, f)
	if err != nil {
		log.Error().Err(err).Msg("error uploading file")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	userEntity, err := h.UpdateImageByUserUuid(ctx, u.Uuid, UpdateImageRequest{ImageID: r.ID, ImageURL: r.URL})
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	// if err := os.Remove(tmpFile); err != nil {
	// 	log.Warn().Err(err).Msgf("cannot remove file %s", tmpFile)
	// }

	authenticatedUser := user.ToAuthenticatedUser(userEntity)
	ctx.JSON(http.StatusOK, authenticatedUser)
}

func getFileName(file *multipart.FileHeader, userUuid uuid.UUID) (string, error) {
	ext, err := getFileExtension(file)
	if err != nil {
		return "", err
	}

	now := time.Now()
	nowAsString := now.Format("20060102150405")
	filename := userUuid.String() + "_" + nowAsString + ext
	return filename, nil
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
