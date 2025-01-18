FROM golang:latest AS builder

WORKDIR /usr/src/app

COPY go.mod go.sum ./

RUN go mod download && go mod verify && \
    go install golang.org/x/tools/gopls@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

COPY . .

RUN go generate ./... && \
    gofmt -s -d ./ && \
    GOFLAGS="-buildvcs=false" golangci-lint run -v --timeout 5m && \
    go test -v -race ./... && \
    go build \
    -trimpath \
    -ldflags="-s -w -extldflags=-static" \
    -tags="osusergo netgo static_build" \
    -o /server \
    cmd/kagi/*.go && \
    rm -rf /usr/src/app

FROM scratch AS final

COPY --from=builder /server /

ENTRYPOINT ["/server"]
