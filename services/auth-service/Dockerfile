FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/app ./services/auth-service

FROM gcr.io/distroless/base
COPY --from=build /bin/app /app
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app"]
