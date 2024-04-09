# ------------------------------------------------------------------------
# SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
# SPDX-FileName: ent/Makefile
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------
ENT_ROOT_DIR := ${abspath ${patsubst %/,%,${dir ${lastword ${MAKEFILE_LIST}}}}}

.PHONY: generate-ent
.SILENT: generate-ent
generate-ent: ## Generate ent database types from schema
	printf "Generating ${CYAN}ent${RESET} database types with ${CYAN}go generate${RESET}..."
	go generate ${ENT_ROOT_DIR}
	printf "${GREEN}DONE${RESET}\n"

.PHONY: describe-schemas
.SILENT: describe-schemas
describe-schemas: ## Print descriptions of generated ent schema types
	go run -mod=mod entgo.io/ent/cmd/ent describe ${ENT_ROOT_DIR}/schema
