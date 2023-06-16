FROM ubuntu:22.04
USER root
RUN apt-get update; apt-get install -y git curl wget bash jq fuse-overlayfs uidmap
COPY bin/* /usr/local/bin/
RUN wget https://dl.k8s.io/release/v1.27.2/bin/linux/amd64/kubectl -O /usr/local/bin/kubectl
RUN wget https://tuf.werf.io/targets/releases/1.2.240/linux-amd64/bin/werf -O /usr/local/bin/werf
RUN chmod -R a+x /usr/local/bin/*
ENV ARGOCD_USER_ID=999
RUN groupadd -g $ARGOCD_USER_ID argocd && \
    useradd -r -u $ARGOCD_USER_ID -g argocd argocd && \
    mkdir -p /home/argocd && \
    chown argocd:0 /home/argocd && \
    chmod g=u /home/argocd
ENV USER=argocd
USER $ARGOCD_USER_ID
WORKDIR /home/argocd
