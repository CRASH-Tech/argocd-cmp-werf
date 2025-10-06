FROM golang:1.25.0 AS builder

WORKDIR /app

COPY go.mod go.sum /app/
COPY cmd/ /app/cmd/
RUN go mod download
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o werf_handler cmd/werf-cmp/*.go

FROM ubuntu:22.04
USER root
RUN apt-get update; apt-get install -y git curl wget bash unzip jq fuse-overlayfs uidmap
RUN wget https://dl.k8s.io/release/v1.34.1/bin/linux/amd64/kubectl -O /usr/local/bin/kubectl
RUN wget https://tuf.werf.io/targets/releases/2.47.8/linux-amd64/bin/werf -O /usr/local/bin/werf
RUN wget https://github.com/argoproj-labs/argocd-vault-plugin/releases/download/v1.18.1/argocd-vault-plugin_1.18.1_linux_amd64 -O /usr/local/bin/argocd-vault-plugin
COPY --from=builder /app/werf_handler /usr/local/bin/werf_handler
RUN chmod -R a+x /usr/local/bin/*
COPY /rbac /home/argocd/rbac
ENV ARGOCD_USER_ID=999
RUN groupadd -g $ARGOCD_USER_ID argocd && \
   useradd -r -u $ARGOCD_USER_ID -g argocd argocd && \
   mkdir -p /home/argocd && \
   chown argocd:0 /home/argocd && \
   chmod g=u /home/argocd
ENV USER=argocd
USER $ARGOCD_USER_ID
WORKDIR /home/argocd
