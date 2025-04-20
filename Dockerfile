# Example : https://github.com/GoogleCloudPlatform/golang-samples/blob/main/run/helloworld/Dockerfile
# Build the application from source
FROM golang:1.24.2 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /go-auth-rbac-starter ./cmd/. 

# Copy necessary files to the /app directory
COPY ./config.yaml ./config.yaml
COPY ./message/templates ./message/templates/
# RUN ls -alh /app/message/templates

# Deploy the application binary into a lean image
FROM alpine:3 AS run

WORKDIR /

COPY --from=build /go-auth-rbac-starter /go-auth-rbac-starter
COPY --from=build /app/config.yaml /config.yaml
COPY --from=build /app/message/templates /message/templates/

EXPOSE 9002

USER 1000:1000

ENTRYPOINT [ "/go-auth-rbac-starter" ]
