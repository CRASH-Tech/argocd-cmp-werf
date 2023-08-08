package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	ARGOCD_APP_NAME            string
	ARGOCD_NAMESPACE           string
	ARGOCD_APP_SOURCE_REPO_URL string

	WERF_CACHE_DISABLED bool

	VAULT_ENABLED                  bool
	VAULT_ADDR                     string
	VAULT_ADMIN_ROLE               string
	VAULT_ADMIN_SA                 string
	VAULT_AUTH_METHOD              string
	VAULT_POLICIES                 []string
	VAULT_ALLOW_PATHS              []string
	VAULT_ENV_SECRETS              []string
	VAULT_TENANT                   string
	VAULT_APP_TOKEN                string
	VAULT_TOKEN_TTL                int32
	VAULT_CREATE_KUBERETES_ENGINES bool

	PROJECT  string
	ENV      string
	APP      string
	INSTANCE string
)

func init() {
	if len(os.Args) <= 1 {
		log.Panic("no command")
	}
}

func main() {
	switch cmd := os.Args[1]; cmd {
	case "init":
		err := setEnv(true)
		if err != nil {
			log.Panic(err)
		}
		err = Init()
		if err != nil {
			log.Panic(err)
		}
	case "render":
		err := setEnv(false)
		if err != nil {
			log.Panic(err)
		}
		err = Render()
		if err != nil {
			log.Panic(err)
		}
	default:
		log.Panic("unknown command")
	}
}

func Init() error {
	if isNeedRegistry() {
		log.Info("Login into registry...")
		os.Remove(fmt.Sprintf("/tmp/%s", ARGOCD_APP_NAME))
		out, err := Cmd("werf cr login ${REGISTRY}")
		if err != nil {
			return err
		}

		fmt.Print(out)
	}

	return nil
}

func Render() error {
	var cmd string
	if VAULT_ENABLED {
		os.Setenv("AVP_TYPE", "vault")
		os.Setenv("AVP_AUTH_TYPE", "token")
		os.Setenv("VAULT_TOKEN", VAULT_APP_TOKEN)

		cmd = "set -o pipefail; werf render --set-docker-config-json-value | argocd-vault-plugin generate -"
	} else {
		cmd = "werf render --set-docker-config-json-value"
	}

	out, err := Cmd(cmd)
	if err != nil {
		return err
	}

	fmt.Print(out)

	return err
}
