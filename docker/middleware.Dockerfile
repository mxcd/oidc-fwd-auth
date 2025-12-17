ARG DOCKERHUB_REGISTRY=docker.io


FROM ${DOCKERHUB_REGISTRY}/library/golang:1.25.4 AS build

WORKDIR /usr/src
COPY go.mod /usr/src/go.mod
COPY go.sum /usr/src/go.sum

RUN go mod download

COPY cmd /usr/src/cmd
COPY internal /usr/src/internal
COPY pkg /usr/src/pkg

RUN CGO_ENABLED=0 go build -o /usr/app/middleware /usr/src/cmd/middleware/main.go

FROM ${DOCKERHUB_REGISTRY}/library/alpine:3.23.0

WORKDIR /usr/app
RUN chown -R 1000:1000 /usr/app

COPY --from=build --chown=1000:1000 /usr/app/middleware /usr/app/middleware

USER 1000:1000
ENTRYPOINT ["/usr/app/middleware"]
