FROM golang:1.26.8-alpine AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -o /acl-manager ./cmd/acl-manager

FROM alpine:3.23
RUN apk add --no-cache iptables-legacy \
    && mkdir /state \
    && chown 10001:10001 /state
COPY --from=build /acl-manager /usr/local/bin/acl-manager
ENV ACL_STATE_DIR=/state
WORKDIR /state
ENTRYPOINT ["/usr/local/bin/acl-manager"]
