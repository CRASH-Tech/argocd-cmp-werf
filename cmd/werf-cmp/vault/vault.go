package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/CRASH-Tech/argocd-cmp-werf/cmd/werf-cmp/types"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	log "github.com/sirupsen/logrus"
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

func (v *Vault) Login(saToken, role, mountPath string) (token, endityId string, err error) {
	resp, err := v.client.Auth.KubernetesLogin(
		context.Background(),
		schema.KubernetesLoginRequest{
			Jwt:  saToken,
			Role: role,
		},
		vault.WithMountPath(mountPath),
	)
	if err != nil {
		return "", "", err
	}

	token = resp.Auth.ClientToken
	endityId = resp.Auth.EntityID

	return
}

func (v *Vault) CreateAuthRoleKubernetes(token, role, mountPath string, boundServiceAccountNames, boundServiceAccountNamespaces, policies []string, ttl int32) error {
	err := v.client.SetToken(token)
	if err != nil {
		return err
	}

	data := schema.KubernetesWriteAuthRoleRequest{
		BoundServiceAccountNames:      boundServiceAccountNames,
		BoundServiceAccountNamespaces: boundServiceAccountNamespaces,
		Policies:                      policies,
		TokenTtl:                      ttl,
		TokenMaxTtl:                   ttl,
	}

	_, err = v.client.Auth.KubernetesWriteAuthRole(context.Background(), role, data, vault.WithMountPath(mountPath))
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) SetEntity(token, entityId, entityName string, policies []string, metadata map[string]interface{}) error {
	err := v.client.SetToken(token)
	if err != nil {
		return err
	}

	data := schema.EntityUpdateByIdRequest{
		Name:     entityName,
		Policies: policies,
		Metadata: metadata,
	}

	_, err = v.client.Identity.EntityUpdateById(context.Background(), entityId, data)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) SetPolicy(token, policyName, policyData string) error {
	err := v.client.SetToken(token)
	if err != nil {
		return err
	}

	data := schema.PoliciesWriteAclPolicyRequest{
		Policy: policyData,
	}

	_, err = v.client.System.PoliciesWriteAclPolicy(context.Background(), policyName, data)
	if err != nil {
		return err
	}

	return nil
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

func (v *Vault) EnableKubernetesEngine(vaultToken string, clusterConfig types.KubernetesClusterSecret) error {
	err := v.client.SetToken(vaultToken)
	if err != nil {
		return err
	}

	data := schema.MountsEnableSecretsEngineRequest{
		Type: "kubernetes",
	}

	resp, err := v.client.System.MountsEnableSecretsEngine(
		context.Background(),
		clusterConfig.Name,
		data,
	)

	log.Info(resp, err)

	conf := make(map[string]interface{})
	conf["kubernetes_host"] = clusterConfig.Server
	conf["kubernetes_ca_cert"] = clusterConfig.Config.TlsClientConfig.CaData
	if clusterConfig.Config.BearerToken != "" {
		conf["service_account_jwt"] = clusterConfig.Config.BearerToken
	} else {
		conf["service_account_jwt"] = clusterConfig.Config.TlsClientConfig.KeyData
	}

	resp, err = v.client.Write(
		context.Background(),
		fmt.Sprintf("/%s/config", clusterConfig.Name),
		conf,
	)

	log.Info(resp, err)

	return nil
}
