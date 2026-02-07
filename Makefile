.PHONY: all

FLAGS :=

all:
	go build $(FLAGS) -o bpfviewer main.go ins.go

debug: FLAGS+=-gcflags=all="-N -l"
debug: all

clean:
	rm -f bpfviewer
