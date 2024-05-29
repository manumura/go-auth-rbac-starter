run:
	@echo "Running the program..."
	go run main.go

test:
	go test -v -cover -short ./...

air:
	@echo "Running the program with air..."
	@air

proto:
	@echo "Generating proto files"
	rm -f pb/*.go
	protoc --proto_path=proto --go_out=pb --go_opt=paths=source_relative \
		--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
		proto/*.proto

sqlc:
	sqlc generate

migrate-status:
	goose -dir "db/sql/migration" sqlite3 ./demo-auth-rbac.db status

migrate-version:
	goose -dir "db/sql/migration" sqlite3 ./demo-auth-rbac.db version

# make migrate-create NAME=create_users_table
migrate-create:
	goose -dir "db/sql/migration" sqlite3 ./demo-auth-rbac.db create $(NAME) sql

migrate-up:
	goose -dir "db/sql/migration" sqlite3 ./demo-auth-rbac.db up

migrate-up-by-one:
	goose -dir "db/sql/migration" sqlite3 ./demo-auth-rbac.db up-by-one

migrate-down:
	goose -dir "db/sql/migration" sqlite3 ./demo-auth-rbac.db down

migrate-reset:
	goose -dir "db/sql/migration" sqlite3 ./demo-auth-rbac.db reset

.PHONY: run test air proto sqlc migrate-status migrate-up migrate-up-by-one migrate-down migrate-version migrate-create
