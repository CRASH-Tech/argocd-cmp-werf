#!/bin/bash

export VAULT_ENABLED='true'

export VAULT_ADDR='https://vault.local'
export VAULT_AUTH_METHOD=k-root
export VAULT_TENANT=xfix

export VAULT_ADMIN_SA=argo-stack-argocd-repo-server
export VAULT_ADMIN_ROLE=xfix_argo-stack

export VAULT_POLICY_0="test_policy2"

export VAULT_ALLOW_PATH_0="read, list;infra/deploy/generic/*"
export VAULT_ALLOW_PATH_1="read, list;{{identity.entity.metadata.app}}/*/{{identity.entity.metadata.env}}/*"


export VAULT_ENV_SECRETS_0="infra/deploy/generic/cd"

export ARGOCD_APP_NAME=home-xfix-demo-app
export ARGOCD_APP_SOURCE_REPO_URL="https://localhost.localdomain/sipve/proxy.git"

export GIT_REF=master
export PROJECT=xfix
export ENV=home
export APP=demo-app
export INSTANCE=stand-va1
export RELEASE=home-xfix-demo-app

export WERF_ENV=home
export WERF_RELEASE=home-xfix-demo-app
export WERF_NAMESPACE=demo-app
export WERF_VALUES_0=.helm/values.home.yaml
export WERF_SET_ENV=global.env=home
export WERF_SET_PROJECT=global.project=xfix
export WERF_SET_APP=global.app=demo-app
export WERF_SET_GIT_REF=global.gitRef=master
export WERF_SET_CLUSTER=global.cluster=in-cluster
export WERF_SET_RELEASE=global.release=home-xfix-demo-app

export WERF_CACHE_DISABLED='false'

# export WERF_BUILDAH_MODE=native-chroot
# export WERF_BUILDAH_STORAGE_DRIVER=overlay
export WERF_LOOSE_GITERMINISM='true'
export WERF_SKIP_BUILD='true'
export WERF_SKIP_DEPENDENCIES_REPO_REFRESH='true'
export WERF_SYNCHRONIZATION='https://werf-sync.local'


go build -o werf_handler cmd/werf-cmp/*.go

./werf_handler init
./werf_handler render