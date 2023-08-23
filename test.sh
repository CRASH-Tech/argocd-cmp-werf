#!/bin/bash

export VAULT_ENABLED='true'

export VAULT_SKIP_VERIFY='true'

export VAULT_ADDR='https://vault.localdomain'
export VAULT_AUTH_METHOD=k-root
export VAULT_AUTH_ROLE=xfix_argo-stack
export VAULT_TENANT=xfix
export VAULT_TOKEN_TTL=1h
export VAULT_TOKEN_NUM_USES=100

#export VAULT_POLICY_0="test_policy2"

export VAULT_ALLOW_PATH_0="read, list;{{identity.entity.metadata.env}}/{{identity.entity.metadata.app}}/*"
export VAULT_ALLOW_PATH_1="read, list;infra/deploy/xfix/cd"
export VAULT_ALLOW_PATH_3="read, list;home/demo-app/*"
export VAULT_ALLOW_PATH_TLS="read, list;tls/*"

export VAULT_CREATE_KUBERETES_ENGINES="true"
export VAULT_CREATE_APP_ROLES="false"
export VAULT_CREATE_CLUSTER_ROLES="false"
export VAULT_OIDC_CREATE_USER_ROLES="true"
export VAULT_OIDC_METHOD=oidc
export VAULT_OIDC_ALLOW_GROUPS="admins, users"

export VAULT_ENV_SECRETS_0="infra/deploy/xfix/cd"

export ARGOCD_APP_NAME=home-xfix-demo-app
export ARGOCD_APP_NAMESPACE=demo-app
export ARGOCD_APP_SOURCE_REPO_URL="https://localhost.localdomain/sipve/proxy.git"

export GIT_REF=master
export PROJECT=xfix
export ENV=home
export APP=demo-app
export INSTANCE=stand-va1
export RELEASE=home-xfix-demo-app
export CLUSTER=k-root

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
#export WERF_SYNCHRONIZATION='https://werf-sync.localdomain'


go build -o werf_handler cmd/werf-cmp/*.go

RESULT=$?
if [ $RESULT != 0 ]; then
  exit 1
fi

./werf_handler init
./werf_handler render
