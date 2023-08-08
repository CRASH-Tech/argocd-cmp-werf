package types

type VaultTokens struct {
	SaAdminToken    string
	SaAppToken      string
	VaultAdminToken string
	VaultAppToken   string
	AppEntityId     string
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
