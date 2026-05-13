.PHONY: build clean test run-phase-a run-phase-b run-phase-c

BINARY := waf-benchmark
GO := go
GOFLAGS := -ldflags="-s -w"

build:
	$(GO) build $(GOFLAGS) -o $(BINARY) .

clean:
	rm -f $(BINARY)
	rm -rf reports/

test:
	$(GO) test ./...

run-phase-a-basic:
	./$(BINARY) -p a --payload-tier basic -o ./reports/phase_a

run-phase-a-advanced:
	./$(BINARY) -p a --payload-tier advanced -o ./reports/phase_a

run-phase-a-bypass:
	./$(BINARY) -p a --payload-tier bypass -o ./reports/phase_a

run-phase-a-all:
	./$(BINARY) -p a --payload-tier all -o ./reports/phase_a

run-phase-b:
	./$(BINARY) -p b -o ./reports/phase_b

run-phase-c:
	./$(BINARY) -p c -o ./reports/phase_c

run-phase-c-dry:
	./$(BINARY) -p c -o ./reports/phase_c --dry-run

run-phase-e:
	./$(BINARY) -p e -o ./reports/phase_e

run-phase-e-dry:
	./$(BINARY) -p e -o ./reports/phase_e --dry-run

all: build
