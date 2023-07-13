package vault

import (
	"context"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type Vault struct {
	client *vault.Client
}

func New(vaultAddress string) (*Vault, error) {
	client, err := vault.New(
		vault.WithAddress(vaultAddress),
		vault.WithRequestTimeout(30*time.Second),
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

func (v *Vault) CreateAuthRoleKubernetes(token, role, mountPath string, boundServiceAccountNames, boundServiceAccountNamespaces, policies []string) error {
	err := v.client.SetToken(token)
	if err != nil {
		return err
	}

	data := schema.KubernetesWriteAuthRoleRequest{
		BoundServiceAccountNames:      boundServiceAccountNames,
		BoundServiceAccountNamespaces: boundServiceAccountNamespaces,
		Policies:                      policies,
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
