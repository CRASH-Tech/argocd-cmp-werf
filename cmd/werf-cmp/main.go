package main

import (
	"fmt"
	"os"

	"github.com/CRASH-Tech/argocd-cmp-werf/cmd/werf-cmp/vault"
	log "github.com/sirupsen/logrus"
)

var (
	ARGOCD_APP_NAME  string
	ARGOCD_NAMESPACE string

	VAULT_ENABLED     bool
	VAULT_ADDR        string
	VAULT_ADMIN_ROLE  string
	VAULT_AUTH_METHOD string
	VAULT_POLICIES    []string
	VAULT_ALLOW_PATHS []string
	VAULT_APP_TOKEN   string

	PROJECT  string
	ENV      string
	APP      string
	INSTANCE string
)

func init() {
	if len(os.Args) <= 1 {
		log.Panic("no command")
	}

	getEnv()
}

func main() {

	switch cmd := os.Args[1]; cmd {
	case "init":
		Init()
	case "render":
		Render()
	default:
		log.Panic("unknown command")
	}

}

func Init() {
	log.Info(fmt.Sprintf("Init %s...", ARGOCD_APP_NAME))

	if VAULT_ENABLED {
		vaultInit()
	}
}

func Render() {

}

func vaultInit() {
	log.Info("Vault init...")
	vault, err := vault.New(VAULT_ADDR)
	if err != nil {
		log.Panic(err)
	}

	log.Info("Create admin SA token...")
	saAdminToken, err := createAppToken(os.Getenv("VAULT_ADMIN_SA"), "1h")
	if err != nil {
		log.Panic(err)
	}

	log.Info("Create app SA token...")
	saAppToken, err := createAppToken(os.Getenv("ARGOCD_APP_NAME"), "1h")
	if err != nil {
		log.Panic(err)
	}

	log.Info("Get vault admin token...")
	adminToken, _, err := getVaultAuthToken(vault, saAdminToken, VAULT_ADMIN_ROLE)
	if err != nil {
		log.Panic(err)
	}

	log.Info("Create vault app auth role...")
	err = createAppAuthRole(vault, adminToken)
	if err != nil {
		log.Panic(err)
	}

	log.Info("Create vault app policy...")
	err = createAppPolicy(vault, adminToken)
	if err != nil {
		log.Panic(err)
	}

	log.Info("Get vault app token...")
	appToken, appEntityId, err := getVaultAuthToken(vault, saAppToken, ARGOCD_APP_NAME)
	if err != nil {
		log.Panic(err)
	}
	VAULT_APP_TOKEN = appToken

	log.Info("Create vault app entity...")
	err = createAppAuthEntity(vault, adminToken, appEntityId)
	if err != nil {
		log.Panic(err)
	}
}

func createAppAuthRole(vault *vault.Vault, adminToken string) error {
	err := vault.CreateAuthRoleKubernetes(
		adminToken,
		ARGOCD_APP_NAME,
		VAULT_AUTH_METHOD,
		[]string{ARGOCD_APP_NAME},
		[]string{ARGOCD_NAMESPACE},
		VAULT_POLICIES,
	)

	return err
}

func getVaultAuthToken(vault *vault.Vault, saToken, role string) (token, entityId string, err error) {
	token, entityId, err = vault.Login(
		saToken,
		role,
		VAULT_AUTH_METHOD,
	)

	return
}

func createAppAuthEntity(vault *vault.Vault, adminToken, appEntityId string) error {

	metadata := map[string]interface{}{
		"project":  PROJECT,
		"env":      ENV,
		"app":      APP,
		"instance": INSTANCE,
	}

	err := vault.SetEntity(
		adminToken,
		appEntityId,
		ARGOCD_APP_NAME,
		VAULT_POLICIES,
		metadata,
	)
	if err != nil {
		return err
	}

	return nil
}

func createAppPolicy(vault *vault.Vault, adminToken string) error {
	var policy string

	for _, path := range VAULT_ALLOW_PATHS {
		policy = policy + fmt.Sprintf(`
		path "%s" {
		  capabilities = ["read", "list"]
		}
		`, path)
	}

	err := vault.SetPolicy(
		adminToken,
		ARGOCD_APP_NAME,
		policy,
	)

	return err
}
