include tools/common.mk

build: echo
	mkdir -p ${OUT}
	(cd cmd && go build -o ${OUT}/meshauth ./meshauth)


push: build
	$(MAKE) _push BIN=meshauth

BUILD_DIR?=/ws/out

wasm/meshauth:
	docker run --rm -v $(shell pwd)/..:/src  -u $(shell id -u) \
      -v ${BUILD_DIR}/tinygo:/home/tinygo \
      -e HOME=/home/tinygo \
      -w /src/meshauth tinygo/tinygo:0.26.0 tinygo build -o /home/tinygo/wasm.wasm -target=wasm ./wasm/
