FROM golang:latest AS builder
LABEL maintainer="821869798@qq.com"
ARG THREADS="4"
ARG SHA=""

# build minimized
WORKDIR /
RUN git clone https://github.com/821869798/easysub --depth=1 && \
    cd easysub && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o easysub ./main.go

FROM alpine:latest

# copy config file & copy execute file
COPY --from=builder /easysub/workdir /workdir/
COPY --from=builder /easysub/easysub /workdir/easysub

# copy local config file into docker
COPY /docs/docker_example /workdir/

# set work dir
WORKDIR /workdir

# modify config (optional)
Run cp pref.example.toml pref.toml -f && \
    sed -i '/key = "clash.log_level"/{N;s/value = "info"/value = "warning"/}' pref.toml && \
    sed -i '/key = "singbox.log_level"/{N;s/value = "info"/value = "warn"/}' pref.toml 

EXPOSE 25500/tcp

ENTRYPOINT ["/workdir/easysub"]