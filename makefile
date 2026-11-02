####### Usage #######
# Build image (required): make build
# Open a shell: make shell
# Entire pipeline: make run GOLDRUSH_ARGS="..." FUZZER_ARGS="..."
# Only first step: make goldrush GOLDRUSH_ARGS="..." 
# Only second step: make fuzzer FUZZER_ARGS="..."
#####################

IMAGE ?= goldrush
UID   := $(shell id -u)
GID   := $(shell id -g)

GOLDRUSH_ARGS ?=
FUZZER_ARGS   ?=

FUZZER_BIN := Fuzzer/target/release/fuzzer
FUZZER_SRC := $(shell find Fuzzer/src -type f 2>/dev/null) Fuzzer/Cargo.toml $(wildcard Fuzzer/Cargo.lock) $(wildcard Fuzzer/build.rs)

DOCKER_RUN = docker run --rm -it \
	-v $(CURDIR):/goldrush \
	-w /goldrush \
	$(IMAGE)

.PHONY: build shell goldrush fuzzer run clean-image

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

# Compile only if the binary is missing or the sources are changed
$(FUZZER_BIN): $(FUZZER_SRC)
	$(DOCKER_RUN) bash -c "cd Fuzzer && cargo build --release"

fuzzer: $(FUZZER_BIN)
	$(DOCKER_RUN) bash -c "cp targets.json Fuzzer/targets.json && cd Fuzzer && ./target/release/fuzzer $(FUZZER_ARGS)"

run:
	$(MAKE) goldrush
	$(MAKE) fuzzer

clean-image:
	docker rmi $(IMAGE)
