package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
)

var (
	ErrNotFound = fmt.Errorf("this is an error")
)

type ValidationError struct {
	customError string
}

func (e *ValidationError) Error() string {
	return "Invalid request"
}

func TestMapSimpleErrorToStatusCode(t *testing.T) {
	// Arrange
	router := gin.Default()
	router.Use(
		ErrorHandler(
			Map(ErrNotFound).ToStatusCode(http.StatusNotFound),
		))

	// Act
	router.GET("/", func(c *gin.Context) {
		_ = c.Error(ErrNotFound)
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))

	// Assert
	assert.Equal(t, recorder.Result().StatusCode, http.StatusNotFound)
}

func TestMapErrorStructToStatusCode(t *testing.T) {
	// Arrange
	router := gin.Default()
	router.Use(
		ErrorHandler(
			Map(&ValidationError{}).ToStatusCode(http.StatusBadRequest),
		))

	// Act
	router.GET("/", func(c *gin.Context) {
		_ = c.Error(&ValidationError{})
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))

	// Assert
	assert.Equal(t, recorder.Result().StatusCode, http.StatusBadRequest)
}

func TestMapErrorResponseFunc(t *testing.T) {
	// Arrange
	router := gin.Default()
	router.Use(
		ErrorHandler(
			Map(ErrNotFound).ToResponse(func(c *gin.Context, err error) {
				c.Status(http.StatusNotFound)
				c.Writer.Write([]byte(err.Error()))
			}),
		))

	// Act
	router.GET("/", func(c *gin.Context) {
		_ = c.Error(ErrNotFound)
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))

	// Assert
	assert.Equal(t, http.StatusNotFound, recorder.Result().StatusCode)
	assert.Equal(t, ErrNotFound.Error(), recorder.Body.String())
}
