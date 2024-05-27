include tools/common.mk

build: echo

BUILD_DIR?=/ws/out

wasm/meshauth:
	mkdir -p /tmp/tinygo
	docker run --rm -v $(shell pwd)/..:/src  -u $(shell id -u) \
      -v ${BUILD_DIR}/tinygo:/home/tinygo \
      -e HOME=/home/tinygo \
      -w /src/meshauth tinygo/tinygo:0.26.0 tinygo build -o /home/tinygo/wasm.wasm -target=wasm ./wasm/

