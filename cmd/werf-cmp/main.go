package main

import (
	"fmt"
	"os"

	"github.com/CRASH-Tech/argocd-cmp-werf/cmd/werf-cmp/types"
	"github.com/CRASH-Tech/argocd-cmp-werf/cmd/werf-cmp/vault"
	log "github.com/sirupsen/logrus"
)

func init() {
	if len(os.Args) <= 1 {
		log.Panic("no command")
	}
}

func main() {
	env, err := GetEnv()
	if err != nil {
		log.Panic(err)
	}

	var v *vault.Vault
	var vEnv types.VaultEnv
	if env.VAULT_ENABLED {
		v, err = vault.New(env.VAULT_ADDR)
		if err != nil {
			log.Panic(err)
		}

		vEnv, err = GetVaultEnv(v, env)
		if err != nil {
			log.Panic(err)
		}
	}

	switch cmd := os.Args[1]; cmd {
	case "init":
		err = Init(env, v, vEnv)
		if err != nil {
			log.Panic(err)
		}

	case "render":
		err = Render(env, v, vEnv)
		if err != nil {
			log.Panic(err)
		}
	default:
		log.Panic("unknown command")
	}
}

func Init(env types.Env, vault *vault.Vault, vaultEnv types.VaultEnv) error {
	if env.VAULT_ENABLED {
		err := SetVault(vault, env, vaultEnv)
		if err != nil {
			return err
		}
	}

	return nil
}

func Render(env types.Env, vault *vault.Vault, vaultEnv types.VaultEnv) error {
	var cmd string
	if env.VAULT_ENABLED {
		SetVaultEnv(vault, env, vaultEnv)
		os.Setenv("AVP_TYPE", "vault")
		os.Setenv("AVP_AUTH_TYPE", "token")
		os.Setenv("VAULT_TOKEN", vaultEnv.VAULT_TOKEN)

		cmd = "set -o pipefail; werf render --set-docker-config-json-value | argocd-vault-plugin generate -"
	} else {
		cmd = "werf render --set-docker-config-json-value"
	}

	if isNeedRegistry() {
		gitPath, err := parseGitUrl(env.ARGOCD_APP_SOURCE_REPO_URL)
		if err != nil {
			return err
		}
		os.Setenv("DOCKER_CONFIG", fmt.Sprintf("/tmp/%s", env.ARGOCD_APP_NAME))

		if env.WERF_CACHE_DISABLED {
			os.Setenv("WERF_REPO", fmt.Sprintf("%s/%s/%s", os.Getenv("REGISTRY"), os.Getenv("PROJECT"), gitPath))
		} else {
			os.Setenv("WERF_REPO", fmt.Sprintf("%s/%s/cache", os.Getenv("REGISTRY"), os.Getenv("PROJECT")))
			os.Setenv("WERF_FINAL_REPO", fmt.Sprintf("%s/%s/%s", os.Getenv("REGISTRY"), os.Getenv("PROJECT"), gitPath))
		}

		os.Remove(fmt.Sprintf("/tmp/%s", env.ARGOCD_APP_NAME))
		_, err = Cmd("werf cr login ${REGISTRY}")
		if err != nil {
			return err
		}
	}

	out, err := Cmd(cmd)
	if err != nil {
		return err
	}

	fmt.Print(out)

	return nil
}
