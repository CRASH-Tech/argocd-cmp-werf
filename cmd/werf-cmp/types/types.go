package types

type Env struct {
	ENV                        string
	APP                        string
	CLUSTER                    string
	ARGOCD_APP_NAME            string
	ARGOCD_APP_NAMESPACE       string
	ARGOCD_NAMESPACE           string
	ARGOCD_APP_SOURCE_REPO_URL string

	WERF_CACHE_DISABLED bool

	VAULT_ENABLED     bool
	VAULT_ADDR        string // https://vault.local
	VAULT_AUTH_METHOD string // k-root
	VAULT_AUTH_ROLE   string // xfix_argo-stack
	VAULT_TENANT      string // xfix

	VAULT_POLICIES    []string // VAULT_POLICY_0="test_policy"
	VAULT_ALLOW_PATHS []string // VAULT_ALLOW_PATH_0="read, list;home/demo-app/*"
	VAULT_ENV_SECRETS []string // VAULT_ENV_SECRETS_0="infra/deploy/xfix/cd"

	VAULT_TOKEN_TTL                string // (OPTIONAL) 1h
	VAULT_TOKEN_NUM_USES           int32  // (OPTIONAL) 0
	VAULT_CREATE_KUBERETES_ENGINES bool
	VAULT_CREATE_APP_ROLES         bool
	VAULT_CREATE_CLUSTER_ROLES     bool
	VAULT_OIDC_CREATE_USER_ROLES   bool
	VAULT_OIDC_METHOD              string
	VAULT_OIDC_ALLOW_GROUPS        []string
}

type VaultEnv struct {
	VAULT_ADMIN_TOKEN string
	VAULT_TOKEN       string
}

type KubernetesClusterSecret struct {
	Name   string
	Server string
	Config KubernetesClusterConfig
}

type KubernetesClusterConfig struct {
	BearerToken     string                    `json:"bearerToken"`
	TlsClientConfig KubernetesTlsClientConfig `json:"tlsClientConfig"`
}

type KubernetesTlsClientConfig struct {
	Insecure bool   `json:"insecure"`
	CertData string `json:"certData"`
	KeyData  string `json:"keyData"`
	CaData   string `json:"caData"`
}
