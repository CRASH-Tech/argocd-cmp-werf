package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CRASH-Tech/argocd-cmp-werf/cmd/werf-cmp/types"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type Vault struct {
	client *vault.Client
}

func New(vaultAddress string) (*Vault, error) {
	tls := vault.TLSConfiguration{
		InsecureSkipVerify: os.Getenv("VAULT_SKIP_VERIFY") == "true",
	}

	client, err := vault.New(
		vault.WithAddress(vaultAddress),
		vault.WithRequestTimeout(30*time.Second),
		vault.WithTLS(tls),
	)

	vault := Vault{
		client: client,
	}

	return &vault, err
}

func (v *Vault) Login(saToken, role, mountPath string) (token string, err error) {
	resp, err := v.client.Auth.KubernetesLogin(
		context.Background(),
		schema.KubernetesLoginRequest{
			Jwt:  saToken,
			Role: role,
		},
		vault.WithMountPath(mountPath),
	)
	if err != nil {
		return "", err
	}

	token = resp.Auth.ClientToken

	return
}

func (v *Vault) SetPolicy(token, name, policyData string) error {
	err := v.client.SetToken(token)
	if err != nil {
		return err
	}

	data := schema.PoliciesWriteAclPolicyRequest{
		Policy: policyData,
	}

	_, err = v.client.System.PoliciesWriteAclPolicy(context.Background(), name, data)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) CreateToken(token, name string, policies []string, ttl string, num_uses int32) (string, error) {
	err := v.client.SetToken(token)
	if err != nil {
		return "", err
	}

	data := schema.TokenCreateRequest{
		DisplayName: name,
		NoParent:    true,
		Policies:    policies,
		Ttl:         ttl,
		NumUses:     num_uses,
	}

	resp, err := v.client.Auth.TokenCreate(context.Background(), data, "")
	if err != nil {
		return "", err
	}

	return resp.Auth.ClientToken, nil
}

func (v *Vault) GetSecrets(token, path string) (map[string]string, error) {
	err := v.client.SetToken(token)
	if err != nil {
		return nil, err
	}

	resp, err := v.client.Read(context.Background(), path)
	if err != nil {
		return nil, err
	}

	data, ok := resp.Data["data"].(map[string]interface{})
	if !ok {
		return nil, errors.New("not map interface")
	}

	result := make(map[string]string)
	for k, v := range data {
		result[k] = v.(string)
	}

	return result, nil
}

func (v *Vault) EnableKubernetesEngine(token string, clusterConfig types.KubernetesClusterSecret) error {
	err := v.client.SetToken(token)
	if err != nil {
		return err
	}

	data := schema.MountsEnableSecretsEngineRequest{
		Type: "kubernetes",
	}

	_, err = v.client.System.MountsEnableSecretsEngine(
		context.Background(),
		clusterConfig.Name,
		data,
	)

	if err != nil && !strings.Contains(err.Error(), "400") {
		return err
	}

	conf := make(map[string]interface{})
	conf["kubernetes_host"] = clusterConfig.Server

	caData, err := base64.StdEncoding.DecodeString(clusterConfig.Config.TlsClientConfig.CaData)
	if err != nil {
		return err
	}

	conf["kubernetes_ca_cert"] = string(caData)
	conf["service_account_jwt"] = clusterConfig.Config.BearerToken

	_, err = v.client.Write(
		context.Background(),
		fmt.Sprintf("/%s/config", clusterConfig.Name),
		conf,
	)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) CreateKuberentesRole(token, cluster, name, roleType, defaultTtl, maxTtl string, namespaces []string, rules string) error {
	err := v.client.SetToken(token)
	if err != nil {
		return err
	}

	conf := make(map[string]interface{})
	conf["allowed_kubernetes_namespaces"] = namespaces
	conf["token_max_ttl"] = maxTtl
	conf["token_default_ttl"] = defaultTtl
	conf["kubernetes_role_type"] = roleType
	conf["generated_role_rules"] = rules

	_, err = v.client.Write(
		context.Background(),
		fmt.Sprintf("/%s/roles/%s", cluster, name),
		conf,
	)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) CreateOidcRole(token, name, method string, policies, boundGroups []string) error {
	err := v.client.SetToken(token)
	if err != nil {
		return err
	}

	allowed_redirect_uris := []string{
		fmt.Sprintf("%s/ui/vault/auth/oidc/oidc/callback", v.client.Configuration().Address),
		fmt.Sprintf("%s/oidc/callback", v.client.Configuration().Address),
	}

	boundClaims := make(map[string][]string)
	boundClaims["groups"] = boundGroups

	conf := make(map[string]interface{})
	conf["allowed_redirect_uris"] = allowed_redirect_uris
	conf["oidc_scopes"] = []string{"openid", "profile", "email"}
	conf["user_claim"] = "preferred_username"
	conf["groups_claim"] = "groups"
	conf["token_policies"] = policies
	conf["bound_claims"] = boundClaims

	_, err = v.client.Write(
		context.Background(),
		fmt.Sprintf("/auth/%s/role/%s", method, name),
		conf,
	)
	if err != nil {
		return err
	}

	return nil
}
