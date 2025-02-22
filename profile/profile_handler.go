package profile

import (
	"database/sql"
	"errors"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/common"
	conf "github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/security"
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

// @BasePath /api
// GetProfile godoc
// @Summary get profile
// @Description get profile
// @Tags profile
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} user.User
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/profile [get]
func (h *ProfileHandler) GetProfile(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("get profile for user UUID %s", authenticatedUser.Uuid)
	user, err := h.GetProfileByUserUuid(ctx, authenticatedUser.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}
	ctx.JSON(http.StatusOK, user)
}

// @BasePath /api
// UpdateProfile godoc
// @Summary update profile
// @Description update profile
// @Tags profile
// @Accept json
// @Produce json
// @Param UpdateProfileRequest body UpdateProfileRequest true "Update Profile Request"
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} user.User
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/profile [put]
func (h *ProfileHandler) UpdateProfile(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("update profile for user UUID %s", authenticatedUser.Uuid)
	var req UpdateProfileRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err = h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	_, err = h.UpdateProfileByUserUuid(ctx, authenticatedUser.Uuid, UpdateProfileParams(req))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	u, err := h.GetProfileByUserUuid(ctx, authenticatedUser.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	// Push new user event
	e := user.NewUserChangeEvent(user.UPDATED, u, u.Uuid)
	h.PushUserEvent(e)

	ctx.JSON(http.StatusOK, u)
}

// @BasePath /api
// UpdatePassword godoc
// @Summary update password
// @Description update password
// @Tags profile
// @Accept json
// @Produce json
// @Param UpdatePasswordRequest body UpdatePasswordRequest true "Update Password Request"
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} user.User
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/profile/password [put]
func (h *ProfileHandler) UpdatePassword(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("update password for user UUID %s", authenticatedUser.Uuid)
	var req UpdatePasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err = h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	_, err = h.UpdatePasswordByUserUuid(ctx, authenticatedUser.Uuid, UpdatePasswordParams(req))
	if err != nil {
		statusCode := http.StatusInternalServerError
		if err == exception.ErrNotFound || err == exception.ErrInvalidRequest {
			statusCode = http.StatusBadRequest
		}
		ctx.AbortWithStatusJSON(statusCode, exception.GetErrorResponse(err, statusCode))
		return
	}

	u, err := h.GetProfileByUserUuid(ctx, authenticatedUser.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	// Push new user event
	e := user.NewUserChangeEvent(user.UPDATED, u, u.Uuid)
	h.PushUserEvent(e)

	ctx.JSON(http.StatusOK, u)
}

// @BasePath /api
// UpdateImage godoc
// @Summary update image
// @Description update image
// @Tags profile
// @Accept mpfd
// @Produce json
// @Param image formData file true "image file"
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} user.User
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/profile/image [put]
func (h *ProfileHandler) UpdateImage(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("update image for user UUID %s", authenticatedUser.Uuid)
	file, err := ctx.FormFile("image")
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	filename, err := getFileName(file, authenticatedUser.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.GetErrorResponse(err, http.StatusBadRequest))
		return
	}

	// tmpFile := TmpDir + "/" + filename
	// ctx.SaveUploadedFile(file, tmpFile)

	f, err := file.Open()
	if err != nil {
		log.Error().Err(err).Msg("error opening file")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	client, err := h.StorageService.GetS3Client(ctx, h.Config.AwsRegion)
	if err != nil {
		log.Error().Err(err).Msg("error loading config")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	// Delete old image
	if authenticatedUser.ImageID != "" {
		err = h.StorageService.DeleteObject(ctx, client, h.Config.AwsS3Bucket, authenticatedUser.ImageID)
		if err != nil {
			log.Error().Err(err).Msg("error deleting old image")
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
			return
		}
	}

	// Upload to S3
	res, err := h.StorageService.UploadObject(ctx, client, h.Config.AwsS3Bucket, S3Dir+"/"+filename, f, file.Header.Get("Content-Type"))
	if err != nil {
		log.Error().Err(err).Msg("error uploading file")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	url := res.URL
	if h.Config.AwsCloudFrontDistributionUrl != "" {
		url = h.Config.AwsCloudFrontDistributionUrl + "/" + res.ID
	}

	p := UpdateImageParams{
		ImageID:  res.ID,
		ImageURL: url,
	}
	_, err = h.UpdateImageByUserUuid(ctx, authenticatedUser.Uuid, p)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	// if err := os.Remove(tmpFile); err != nil {
	// 	log.Warn().Err(err).Msgf("cannot remove file %s", tmpFile)
	// }

	u, err := h.GetProfileByUserUuid(ctx, authenticatedUser.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	// Push new user event
	e := user.NewUserChangeEvent(user.UPDATED, u, u.Uuid)
	h.PushUserEvent(e)

	ctx.JSON(http.StatusOK, u)
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

// @BasePath /api
// DeleteProfile godoc
// @Summary delete profile
// @Description delete profile
// @Tags profile
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} common.MessageResponse
// @Failure 400 {object} exception.ErrorResponse
// @Failure 401 {object} exception.ErrorResponse
// @Failure 403 {object} exception.ErrorResponse
// @Failure 404 {object} exception.ErrorResponse
// @Failure 500 {object} exception.ErrorResponse
// @Router /v1/profile [delete]
func (h *ProfileHandler) DeleteProfile(ctx *gin.Context) {
	authenticatedUser, err := security.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	log.Info().Msgf("delete profile for user UUID %s", authenticatedUser.Uuid)
	_, err = h.DeleteProfileByUserUuid(ctx, authenticatedUser.Uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(exception.ErrNotFound, http.StatusNotFound))
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.GetErrorResponse(err, http.StatusInternalServerError))
		return
	}

	u, err := h.GetProfileByUserUuid(ctx, authenticatedUser.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.GetErrorResponse(err, http.StatusNotFound))
		return
	}

	// Push new user event
	e := user.NewUserChangeEvent(user.UPDATED, u, u.Uuid)
	h.PushUserEvent(e)

	ctx.JSON(http.StatusOK, common.MessageResponse{Message: "profile deleted successfully"})
}
