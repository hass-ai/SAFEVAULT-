# Régénère le code Go à partir des fichiers .proto
# (nécessite protoc, protoc-gen-go et protoc-gen-go-grpc).
proto:
	protoc --proto_path=proto \
		--go_out=proto --go_opt=paths=source_relative \
		--go-grpc_out=proto --go-grpc_opt=paths=source_relative \
		proto/*.proto

.PHONY: proto
