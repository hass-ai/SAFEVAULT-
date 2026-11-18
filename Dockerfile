# Image d'un composant SafeVault. Le composant est choisi au build :
#   docker build --build-arg CMD=node .
FROM golang:1.27 AS build
ARG CMD=node
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD} \
 && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENTRYPOINT ["/app"]