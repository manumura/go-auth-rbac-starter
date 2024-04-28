run:
	@echo "Running the program..."
	go run main.go

air:
	@echo "Running the program with air..."
	@air

proto:
	@echo "Generating proto files"
	rm -f pb/*.go
	protoc --proto_path=proto --go_out=pb --go_opt=paths=source_relative \
		--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
		proto/*.proto

.PHONY: run air proto
