package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func GrpcUnaryLogger(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp interface{}, err error) {
	startTime := time.Now()
	result, err := handler(ctx, req)
	duration := time.Since(startTime)

	statusCode := codes.Unknown
	if st, ok := status.FromError(err); ok {
		statusCode = st.Code()
	}

	logger := log.Info()
	if err != nil {
		logger = log.Error().Err(err)
	}

	logger.Str("protocol", "grpc").
		Str("method", info.FullMethod).
		Int("status_code", int(statusCode)).
		Str("status_text", statusCode.String()).
		Dur("duration", duration).
		Msg("received a gRPC request")

	return result, err
}

// func GrpcStreamLogger(
// 	ctx context.Context,
// 	req grpc.ServerStream,
// 	info *grpc.StreamServerInfo,
// 	handler grpc.StreamHandler,
// ) (resp interface{}, err error) {
// 	startTime := time.Now()
// 	err = handler(ctx, req)
// 	duration := time.Since(startTime)

// 	statusCode := codes.Unknown
// 	if st, ok := status.FromError(err); ok {
// 		statusCode = st.Code()
// 	}

// 	logger := log.Info()
// 	if err != nil {
// 		logger = log.Error().Err(err)
// 	}

// 	logger.Str("protocol", "grpc").
// 		Str("method", info.FullMethod).
// 		Int("status_code", int(statusCode)).
// 		Str("status_text", statusCode.String()).
// 		Dur("duration", duration).
// 		Msg("received a gRPC request")

// 	return err
// }

type ResponseRecorder struct {
	http.ResponseWriter
	StatusCode int
	Body       []byte
}

func (rec *ResponseRecorder) WriteHeader(statusCode int) {
	rec.StatusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

func (rec *ResponseRecorder) Write(body []byte) (int, error) {
	rec.Body = body
	return rec.ResponseWriter.Write(body)
}

func HttpLogger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		startTime := time.Now()
		rec := &ResponseRecorder{
			ResponseWriter: res,
			StatusCode:     http.StatusOK,
		}
		handler.ServeHTTP(rec, req)
		duration := time.Since(startTime)

		logger := log.Info()
		if rec.StatusCode != http.StatusOK {
			logger = log.Error().Bytes("body", rec.Body)
		}

		logger.Str("protocol", "http").
			Str("method", req.Method).
			Str("path", req.RequestURI).
			Int("status_code", rec.StatusCode).
			Str("status_text", http.StatusText(rec.StatusCode)).
			Dur("duration", duration).
			Msg("received a HTTP request")
	})
}

// func RequestLogger() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
// 		t := time.Now()

// 		c.Next()

// 		latency := time.Since(t)

// 		fmt.Printf("%d %s %s %s %s\n",
// 		c.Writer.Status(),
// 			c.Request.Method,
// 			c.Request.RequestURI,
// 			c.Request.Proto,
// 			latency,
// 		)
// 	}
// }
