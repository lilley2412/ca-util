FROM golang:1.13 as builder

LABEL maintainer="lilley2412@gmail.com"

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo

FROM alpine:3.10.2

# ARG kube_version

# RUN apk add ca-certificates \
#    && apk update \
#    && apk add jq bash curl openssl

# # TODO - get the kubectl release version from kube_version in build pipeline
# RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v.1.15.0/bin/linux/amd64/kubectl \
#    && chmod +x ./kubectl \
#    && mv ./kubectl /usr/local/bin

WORKDIR /app

COPY --from=builder /app/ca-util .

CMD ["/app/ca-util", "help"]
