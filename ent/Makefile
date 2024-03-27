ENT_ROOT_DIR   := ${abspath ${patsubst %/,%,${dir ${lastword ${MAKEFILE_LIST}}}}}
PROTOC_ENT_VER := eff33e4dca0b84429e6127dc0ec30d866d28895c
PROTOC_ENT_URL := https://raw.githubusercontent.com/ent/contrib/${PROTOC_ENT_VER}/entproto/cmd/protoc-gen-ent/options/ent/opts.proto

.PHONY: generate-ent
.SILENT: generate-ent
generate-ent: proto-ent ## Generate ent database types from schema
	printf "Generating ${CYAN}ent${RESET} database types with ${CYAN}go generate${RESET}..."
	go generate ./pkg/sbom/ent
	echo "${GREEN}DONE${RESET}"

.PHONY: proto-ent
.SILENT: proto-ent
proto-ent: ${ENT_ROOT_DIR}/proto/options/opts.proto ## Compile protobufs with protoc-gen-ent plugin
	mkdir -p ${ENT_ROOT_DIR}/schema

	printf "Compiling protobufs with ${CYAN}protoc-gen-ent${RESET}..."
	protoc \
	  --proto_path=${ENT_ROOT_DIR} \
	  --proto_path=${ENT_ROOT_DIR}/proto \
	  --ent_out=${ENT_ROOT_DIR} \
	  --ent_opt=schemadir=${ENT_ROOT_DIR}/schema \
	  ${ENT_ROOT_DIR}/proto/entpb/sbom.proto
	echo "${GREEN}DONE${RESET}"

	printf "Fixing generated package imports..."
	sed -i 's|gorm.io/gen/field|entgo.io/ent/schema/field|' ${ENT_ROOT_DIR}/schema/*.go
	sed -i 's|github.com/bom-squad/protobom/pkg/sbom/ent/edge|entgo.io/ent/schema/edge|' ${ENT_ROOT_DIR}/schema/*.go
	echo "${GREEN}DONE${RESET}"

	go fmt ${ENT_ROOT_DIR}/schema

.SILENT: ${ENT_ROOT_DIR}/proto/options/opts.proto
${ENT_ROOT_DIR}/proto/options/opts.proto:
	printf "Installing ${CYAN}protoc-gen-ent${RESET}..."
	go install entgo.io/contrib/entproto/cmd/protoc-gen-ent@${PROTOC_ENT_VER}
	echo "${GREEN}DONE${RESET}"

	printf "Downloading ${CYAN}protoc-gen-ent${RESET} protobuf definitions..."
	mkdir -p ${ENT_ROOT_DIR}/proto/options
	curl --fail --silent --show-error --location --output ${ENT_ROOT_DIR}/proto/options/opts.proto --url ${PROTOC_ENT_URL}
	echo "${GREEN}DONE${RESET}"
