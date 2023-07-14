package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/CRASH-Tech/argocd-cmp-werf/cmd/werf-cmp/vault"
	log "github.com/sirupsen/logrus"
)

var (
	ARGOCD_APP_NAME            string
	ARGOCD_NAMESPACE           string
	ARGOCD_APP_SOURCE_REPO_URL string

	VAULT_ENABLED       bool
	VAULT_ADDR          string
	VAULT_ADMIN_ROLE    string
	VAULT_ADMIN_SA      string
	VAULT_AUTH_METHOD   string
	VAULT_POLICIES      []string
	VAULT_ALLOW_PATHS   []string
	VAULT_TENANT        string
	VAULT_APP_TOKEN     string
	VAULT_DEPLOY_SECRET string

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
		vault, err := vault.New(VAULT_ADDR)
		if err != nil {
			log.Panic(err)
		}

		vaultSetup(vault)

		deploySecrets, err := vault.GetSecrets(VAULT_APP_TOKEN, fmt.Sprintf("%s/data/%s", VAULT_TENANT, VAULT_DEPLOY_SECRET))
		if err != nil {
			log.Panic(err)
		}
		for k, v := range deploySecrets {
			os.Setenv(k, v)
		}

		if isNeedRegistry() {
			gitPath, err := parseGitUrl(ARGOCD_APP_SOURCE_REPO_URL)
			if err != nil {
				log.Panic(err)
			}
			os.Setenv("WERF_REPO", fmt.Sprintf("%s/%s/%s/cache", os.Getenv("REGISTRY"), PROJECT, gitPath))
			os.Setenv("WERF_FINAL_REPO", fmt.Sprintf("%s/%s/%s", os.Getenv("REGISTRY"), PROJECT, gitPath))
			os.Setenv("WERF_DOCKER_CONFIG", fmt.Sprintf("/tmp/%s", ARGOCD_APP_NAME))
			os.Remove(fmt.Sprintf("/tmp/%s", ARGOCD_APP_NAME))

			log.Info("Login into registry...")
			out, err := Cmd("werf cr login ${REGISTRY}")
			if err != nil {
				log.Panic(err)
			}
			fmt.Println(out)
		}
	}

}

func parseGitUrl(url string) (string, error) {
	r, err := regexp.Compile(`^(https?|ssh):\/\/([a-zA-Z0-9\.\@\:\-]+)\/(.+).git$`)
	if err != nil {
		log.Panic(err)
	}

	data := r.FindStringSubmatch(ARGOCD_APP_SOURCE_REPO_URL)
	if len(data) != 4 {
		return "", errors.New("cannot parse git url")
	}

	return data[3], nil

}

func Render() {
	var cmd string
	if VAULT_ENABLED {
		vault, err := vault.New(VAULT_ADDR)
		if err != nil {
			log.Panic(err)
		}

		saAppToken, err := createSaToken(ARGOCD_APP_NAME, "1h")
		if err != nil {
			log.Panic(err)
		}

		appToken, _, err := getVaultAuthToken(vault, saAppToken, ARGOCD_APP_NAME)
		if err != nil {
			log.Panic(err)
		}
		os.Setenv("AVP_TYPE", "vault")
		os.Setenv("AVP_AUTH_TYPE", "token")
		os.Setenv("VAULT_TOKEN", appToken)

		cmd = "werf render --set-docker-config-json-value | argocd-vault-plugin generate -"
	} else {
		cmd = "werf render --set-docker-config-json-value"
	}

	out, err := Cmd(cmd)
	if err != nil {
		log.Panic(err)
	}
	fmt.Print(out)

}

func vaultSetup(vault *vault.Vault) {
	log.Info("Vault setup...")

	log.Info("Create admin SA token...")
	saAdminToken, err := createSaToken(VAULT_ADMIN_SA, "1h")
	if err != nil {
		log.Panic(err)
	}

	log.Info("Create app SA token...")
	saAppToken, err := createSaToken(ARGOCD_APP_NAME, "1h")
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

func isNeedRegistry() bool {
	log.Info("Check registry needed...")
	b, err := os.ReadFile("werf.yaml")
	if err != nil {
		log.Panic(err)
	}

	s := string(b)

	return strings.Contains(s, "image:")
}
