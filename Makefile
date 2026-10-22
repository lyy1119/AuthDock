# AuthDock Makefile
#
# 默认目标只打印帮助，不执行任何构建：直接运行 `make` 或 `make help`。
#
# 构建产物：
#   bin/authdock        Linux  x86_64
#   bin/authdock.exe    Windows x86_64
#   dist/               发布包（tar.gz / zip / checksums.txt）
#
# 两个依赖（modernc.org/sqlite、golang.org/x/crypto/argon2）都是纯 Go，
# 因此交叉编译不需要 C 工具链，CGO_ENABLED 默认关闭。

.DEFAULT_GOAL := help

APP         := authdock
BIN_DIR     ?= bin
RELEASE_DIR ?= dist
DB_FILE     ?= data/authdock.db

# 版本信息：优先取 git tag，其次短提交号；CI 可通过环境变量覆盖。
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

GO          ?= go
GOFMT       ?= gofmt
GOFLAGS     ?=
CGO_ENABLED := 0

# 注入 main.go 里的构建元数据（见 `authdock -version`）。
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

# 容器镜像（预留）：GitHub Actions 里可以用
#   make docker-build IMAGE=ghcr.io/<owner>/authdock IMAGE_TAG=${GITHUB_SHA}
IMAGE      ?= ghcr.io/lyy1119/authdock
IMAGE_TAG  ?= $(VERSION)
PLATFORMS  ?= linux/amd64
DOCKERFILE ?= Dockerfile

SHA256 := $(shell command -v sha256sum >/dev/null 2>&1 && echo 'sha256sum' || echo 'shasum -a 256')

.PHONY: help version
.PHONY: build build-linux build-windows build-all run reset-password clean
.PHONY: fmt fmt-check vet tidy test test-race ci
.PHONY: docker-build docker-push docker-manifest
.PHONY: release-artifacts release

##@ 通用

help: ## 显示本帮助（默认目标）
	@printf '\n用法: \033[1mmake <target>\033[0m\n'
	@awk 'BEGIN {FS = ":.*## "} \
		/^##@ / {printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next} \
		/^[a-zA-Z0-9_.-]+:.*## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\n当前版本信息: %s (commit %s, %s)\n\n' '$(VERSION)' '$(COMMIT)' '$(BUILD_DATE)'

version: ## 打印将要注入的版本信息
	@echo "version:    $(VERSION)"
	@echo "commit:     $(COMMIT)"
	@echo "build date: $(BUILD_DATE)"
	@echo "go:         $$($(GO) version)"

##@ 构建

build: build-linux ## 编译 Linux x86_64（等同 build-linux）

build-linux: ## 编译 Linux x86_64 -> bin/authdock
	@mkdir -p $(BIN_DIR)
	@echo "==> linux/amd64   $(BIN_DIR)/$(APP)   ($(VERSION))"
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 \
		$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(APP) .

build-windows: ## 交叉编译 Windows x86_64 -> bin/authdock.exe
	@mkdir -p $(BIN_DIR)
	@echo "==> windows/amd64 $(BIN_DIR)/$(APP).exe ($(VERSION))"
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 \
		$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(APP).exe .

build-all: build-linux build-windows ## 同时构建 Linux 与 Windows

run: ## 本地前台运行（数据库 bin/dev.db）
	@mkdir -p $(BIN_DIR)
	$(GO) run . -addr 127.0.0.1:8080 -db $(BIN_DIR)/dev.db

reset-password: ## 重置 admin 密码并只打印一次（数据库默认 data/authdock.db）
	$(GO) run . -reset-admin-password -db $(DB_FILE)

clean: ## 清理构建产物（bin/ 与 dist/）
	@rm -rf $(BIN_DIR) $(RELEASE_DIR)
	@echo "==> 已清理 $(BIN_DIR)/ $(RELEASE_DIR)/"

##@ 质量检查

fmt: ## 格式化代码（会修改文件）
	$(GO) fmt ./...

fmt-check: ## 校验格式，不改文件（CI 用）
	@unformatted=$$($(GOFMT) -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "以下文件未格式化，请运行 make fmt："; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet: ## go vet 静态检查
	$(GO) vet ./...

tidy: ## 整理 go.mod / go.sum
	$(GO) mod tidy

test: ## 运行单元测试
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

test-race: ## 带 race detector 运行测试（需要 cgo 与 gcc）
	CGO_ENABLED=1 $(GO) test -race ./...

ci: fmt-check vet test build-all ## CI 流水线：格式 + vet + 测试 + 双平台构建

##@ Docker 镜像（预留，等待 Dockerfile 与 GH Actions workflow）
#
# 预留用法（workflow 里直接写这几条即可）：
#   make docker-build IMAGE=ghcr.io/<owner>/authdock IMAGE_TAG=${{ github.sha }}
#   make docker-push  IMAGE=ghcr.io/<owner>/authdock IMAGE_TAG=${{ github.sha }}
# 镜像里建议放静态编译产物（CGO_ENABLED=0）或直接多阶段 go build。

docker-build: ## 预留：构建容器镜像（当前会提示缺少 Dockerfile/docker）
	@command -v docker >/dev/null 2>&1 || { \
		echo "未找到 docker CLI：这是预留给 GitHub Actions 的目标。"; exit 1; }
	@[ -f $(DOCKERFILE) ] || { \
		echo "$(DOCKERFILE) 尚未创建：这是预留给 GitHub Actions 的目标。"; \
		echo "就绪后本目标执行：docker buildx build --platform $(PLATFORMS) -t $(IMAGE):$(IMAGE_TAG) ."; exit 1; }
	docker buildx build --platform $(PLATFORMS) \
		-t $(IMAGE):$(IMAGE_TAG) -t $(IMAGE):latest .

docker-push: ## 预留：构建并推送镜像（需先 docker login）
	@command -v docker >/dev/null 2>&1 || { echo "未找到 docker CLI（预留目标）。"; exit 1; }
	@[ -f $(DOCKERFILE) ] || { echo "$(DOCKERFILE) 尚未创建（预留目标）。"; exit 1; }
	docker buildx build --platform $(PLATFORMS) \
		-t $(IMAGE):$(IMAGE_TAG) -t $(IMAGE):latest --push .

docker-manifest: ## 预留：生成多架构 manifest（前置多平台推送）
	@command -v docker >/dev/null 2>&1 || { echo "未找到 docker CLI（预留目标）。"; exit 1; }
	docker buildx imagetools create -t $(IMAGE):$(IMAGE_TAG) $(IMAGE):$(IMAGE_TAG)-amd64

##@ 发布（预留，发布动作交给 GitHub Actions）

release-artifacts: build-all ## 生成本地发布产物：dist/*.tar.gz、*.zip、checksums.txt
	@rm -rf $(RELEASE_DIR) && mkdir -p $(RELEASE_DIR)/linux $(RELEASE_DIR)/windows
	@cp $(BIN_DIR)/$(APP) LICENSE README.md $(RELEASE_DIR)/linux/
	@cp $(BIN_DIR)/$(APP).exe LICENSE README.md $(RELEASE_DIR)/windows/
	@tar -C $(RELEASE_DIR)/linux -czf $(RELEASE_DIR)/$(APP)_$(VERSION)_linux_amd64.tar.gz $(APP) LICENSE README.md
	@(cd $(RELEASE_DIR)/windows && if command -v zip >/dev/null 2>&1; then \
		zip -qr ../$(APP)_$(VERSION)_windows_amd64.zip $(APP).exe LICENSE README.md; \
	else \
		tar -czf ../$(APP)_$(VERSION)_windows_amd64.tar.gz $(APP).exe LICENSE README.md; \
	fi)
	@rm -rf $(RELEASE_DIR)/linux $(RELEASE_DIR)/windows
	@cd $(RELEASE_DIR) && for f in *.tar.gz *.zip; do \
		if [ -e "$$f" ]; then $(SHA256) "$$f"; fi; \
	done > checksums.txt
	@echo "==> $(RELEASE_DIR)/"
	@ls -1 $(RELEASE_DIR)
	@echo "--- checksums.txt ---"
	@cat $(RELEASE_DIR)/checksums.txt

release: ## 预留：打 tag 后由 GitHub Actions 发布（本地不执行）
	@echo "release 由 GitHub Actions 负责，本地不执行。"
	@echo "  - 尚未添加 .github/workflows/release.yml"
	@echo "  - 本地可先用 'make release-artifacts' 生成 $(RELEASE_DIR)/ 下的产物"
	@echo "  - 计划中的触发方式：git tag vX.Y.Z && git push origin vX.Y.Z"
	@exit 1

# ─────────────────────────────────────────────────────────────────────────────
# 预留：GitHub Actions（workflow 文件尚未添加，目标已就绪）
#
# .github/workflows/ci.yml
#   on: [push, pull_request]
#   steps: make ci                       # fmt-check + vet + test + build-all
#
# .github/workflows/docker.yml
#   on: { push: { branches: [main], tags: ["v*"] } }
#   steps: make docker-build docker-push
#          IMAGE=ghcr.io/${{ github.repository }} IMAGE_TAG=${{ github.sha }}
#
# .github/workflows/release.yml
#   on: { push: { tags: ["v*"] } }
#   steps: make release-artifacts        # 生成 dist/ 下的产物与 checksums
#          softprops/action-gh-release 上传 dist/*
#
# 另外可选的后续扩展（同样预留）：
#   - make docker-manifest 用于多架构镜像
#   - 其他架构：build-linux-arm64 / build-darwin-arm64（当前需求只要求 x86_64）
