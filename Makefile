BIN := freshguard

.PHONY: build test vet fmt samples demo clean

build:
	go build -o $(BIN) ./cmd/freshguard

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

samples: build
	./$(BIN) gen-sample --out data/samples

demo: build samples
	bash examples/demo.sh

clean:
	rm -f $(BIN)
	rm -f /tmp/freshguard-replay.json
