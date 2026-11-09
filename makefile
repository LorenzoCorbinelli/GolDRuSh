####### Usage #######
# Build image (required): make build
# Open a shell: make shell
# With executable: make run-exec GOLDRUSH_ARGS="..." FUZZER_ARGS="..."
# With libraries: make harness GOLDRUSH_ARGS="..." -> check harness.cpp -> make run-lib FUZZER_ARGS="..."
#####################

IMAGE ?= goldrush
UID   := $(shell id -u)
GID   := $(shell id -g)

GOLDRUSH_ARGS ?=
FUZZER_ARGS   ?=

BINARY = $(filter %.so,$(GOLDRUSH_ARGS))	# I'm assuming that the binary is always with .so extension
HARNESS_CONFIG := .binary_name

FUZZER_BIN := fuzzer/target/release/fuzzer
FUZZER_SRC := $(shell find fuzzer/src -type f 2>/dev/null) fuzzer/Cargo.toml $(wildcard fuzzer/Cargo.lock) $(wildcard fuzzer/build.rs)

DOCKER_RUN = docker run --rm -it \
	-v $(CURDIR):/goldrush \
	-w /goldrush \
	$(IMAGE)

.PHONY: build shell goldrush harness fuzzer run clean-image

build:
	docker build -t $(IMAGE) \
		--build-arg UID=$(UID) --build-arg GID=$(GID) .
	mkdir -p log_file
	docker run --rm -u 0 -v $(CURDIR):/goldrush $(IMAGE) \
		chown -R $(UID):$(GID) /goldrush

shell:
	$(DOCKER_RUN) bash

goldrush:
	$(DOCKER_RUN) python goldrush.py $(GOLDRUSH_ARGS)

harness: goldrush
	$(DOCKER_RUN) python3 generate_harness.py --lib ./$(BINARY) --types types.json --out harness.cpp
	@echo "$(BINARY)" > $(HARNESS_CONFIG)	# saving the binary name
	$(DOCKER_RUN) bash -c "mv $(BINARY) $(BINARY:.so=_original.so)"
	$(DOCKER_RUN) bash -c "rm types.json"

# Compile only if the binary is missing or the sources are changed
$(FUZZER_BIN): $(FUZZER_SRC)
	$(DOCKER_RUN) bash -c "cd fuzzer && cargo build --release"

fuzzer: $(FUZZER_BIN)
	$(DOCKER_RUN) bash -c "rm -rf fuzzer/test && mkdir -p fuzzer/test && cp -a test/. fuzzer/test/ && cp targets.json fuzzer/targets.json && cd fuzzer && ./target/release/fuzzer $(FUZZER_ARGS)"

run-exec:
	$(MAKE) goldrush
	$(DOCKER_RUN) bash -c "rm types.json"
	$(MAKE) fuzzer

run-lib:
	@BINARY=$$(cat $(HARNESS_CONFIG) | tr -d '\t\r\n '); \
	OBJ=$${BINARY%.so}.o; \
	$(DOCKER_RUN) bash -c "g++ -std=c++17 -no-pie -g -O1 harness.cpp $$OBJ -o $$BINARY -I."	# The final binary has the original name (it must match the one in targets.json)
	$(MAKE) fuzzer

clean-image:
	docker rmi $(IMAGE)
