.PHONY: all debug clean

FLAGS := -buildvcs=false
LDFLAGS := -w -s

all: 
	mkdir -p build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(FLAGS) -ldflags="$(LDFLAGS) -extldflags=-static" -o build/bpfviewer-amd64 main.go ins.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(FLAGS) -ldflags="$(LDFLAGS) -extldflags=-static" -o build/bpfviewer-arm64 main.go ins.go

debug: FLAGS+=-gcflags=all="-N -l"
debug: LDFLAGS=
debug: all

clean:
	rm -rf build/
