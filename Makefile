## Build variables
TEMPDIR = ./.tmp
PROTOC_VERSION=23.2
ARCH := $(shell uname -m)
OS := $(shell uname -s)

ifeq ($(OS),Linux)
    OS_TYPE := linux
else ifeq ($(OS),Darwin)
    OS_TYPE := osx
else
    $(error Unsupported operating system: $(OS))
endif

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

PROTOC_ZIP=protoc-$(PROTOC_VERSION)-$(OS_TYPE)-$(ARCH).zip
PROTODIR = $(TEMPDIR)/proto
# PROTOC = $(PROTODIR)/bin/protoc 
PROTOC = $(shell which protoc) #  For protoc installed in path used
PROTODIR = $(TEMPDIR)/proto
CDX_SPECDIR =  $(TEMPDIR)/cdx_spec

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

$(PROTODIR):
	mkdir -p $(PROTODIR)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: go_gen
go-gen: ## Generate go protobuf
	$(PROTOC)  --go_out=pkg/ --experimental_allow_proto3_optional  api/cdx/bom-1.3.proto
	$(PROTOC)  --go_out=pkg/ --experimental_allow_proto3_optional  api/cdx/bom-1.4.proto
#	$(PROTOC) --go_out=pkg/ api/sbom.proto
#	$(PROTOC) --go_out=pkg/ api/universal.proto

.PHONY: go_gen
go-cdx: ## Generate go protobuf
	$(PROTOC) --go_out=pkg/ api/sbom.proto
	$(PROTOC) --go_out=pkg/ api/universal.proto


.PHONY: bootstrap-tools 
bootstrap-tools: bootstrap-proto-clean $(PROTODIR)
	cd $(PROTODIR) && curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/$(PROTOC_ZIP)
	cd $(PROTODIR) && unzip $(PROTOC_ZIP)

.PHONY: bootstrap-schemes 
bootstrap-schemes: bootstrap-schemes-clean  $(TEMPDIR)
	git clone https://github.com/CycloneDX/specification.git $(CDX_SPECDIR)

.PHONY: bootstrap-schemes-clean
bootstrap-schemes-clean:
	rm -rf $(CDX_SPECDIR)

.PHONY: bootstrap-proto-clean
bootstrap-proto-clean:
	rm -rf $(PROTODIR)

.PHONY: bootstrap-clean
bootstrap-clean:
	rm -rf $(TEMPDIR)

.PHONY: bootstrap-schemes 
bootstrap: bootstrap-tools bootstrap-schemes  ## Boostrap dependencies for build
	$(call title,Bootstrapping build dependencies)