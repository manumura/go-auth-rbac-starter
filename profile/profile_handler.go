package profile

import (
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

const (
	TmpDir          = "tmp"
	ValidExtensions = ".jpg,.jpeg,.png,.gif"
)

type ProfileHandler struct {
	ProfileService
}

func NewProfileHandler(profileService ProfileService) ProfileHandler {
	return ProfileHandler{
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

	tmpFile := TmpDir + "/" + u.Uuid.String() + "_" + nowAsString + ext
	ctx.SaveUploadedFile(file, tmpFile)

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
