package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/CRASH-Tech/argocd-cmp-werf/cmd/werf-cmp/types"
	"github.com/CRASH-Tech/argocd-cmp-werf/cmd/werf-cmp/vault"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func GetEnv() (types.Env, error) {
	//REMOVE ARGOCD_ENV_ PREFIX
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		os.Setenv(strings.TrimPrefix(pair[0], "ARGOCD_ENV_"), pair[1])
	}

	result := types.Env{}

	result.CLUSTER = os.Getenv("CLUSTER")
	result.ARGOCD_APP_NAME = os.Getenv("ARGOCD_APP_NAME")
	result.ARGOCD_APP_NAMESPACE = os.Getenv("ARGOCD_APP_NAMESPACE")
	result.ARGOCD_APP_SOURCE_REPO_URL = os.Getenv("ARGOCD_APP_SOURCE_REPO_URL")

	result.WERF_CACHE_DISABLED = (os.Getenv("WERF_CACHE_DISABLED") == "true")

	result.VAULT_ENABLED = (os.Getenv("VAULT_ENABLED") == "true")
	result.VAULT_ADDR = os.Getenv("VAULT_ADDR")
	result.VAULT_AUTH_METHOD = os.Getenv("VAULT_AUTH_METHOD")
	result.VAULT_AUTH_ROLE = os.Getenv("VAULT_AUTH_ROLE")
	result.VAULT_TENANT = os.Getenv("VAULT_TENANT")
	result.VAULT_CREATE_KUBERETES_ENGINES = (os.Getenv("VAULT_CREATE_KUBERETES_ENGINES") == "true")
	result.VAULT_CREATE_APP_ROLES = (os.Getenv("VAULT_CREATE_APP_ROLES") == "true")
	result.VAULT_CREATE_CLUSTER_ROLES = (os.Getenv("VAULT_CREATE_CLUSTER_ROLES") == "true")
	result.VAULT_POLICIES = append(result.VAULT_POLICIES, os.Getenv("ARGOCD_APP_NAME"))
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if strings.HasPrefix(pair[0], "VAULT_POLICY_") {
			result.VAULT_POLICIES = append(result.VAULT_POLICIES, pair[1])
		}
		if strings.HasPrefix(pair[0], "VAULT_ALLOW_PATH_") {
			result.VAULT_ALLOW_PATHS = append(result.VAULT_ALLOW_PATHS, pair[1])
		}
		if strings.HasPrefix(pair[0], "VAULT_ENV_SECRETS_") {
			result.VAULT_ENV_SECRETS = append(result.VAULT_ENV_SECRETS, pair[1])
		}
	}

	if ttl, isSet := os.LookupEnv("VAULT_TOKEN_TTL"); isSet {
		result.VAULT_TOKEN_TTL = ttl
	} else {
		result.VAULT_TOKEN_TTL = "87600h"
	}

	if n, isSet := os.LookupEnv("VAULT_TOKEN_NUM_USES"); isSet {
		n, err := strconv.Atoi(n)
		if err != nil {
			return result, errors.New("cannot parse VAULT_TOKEN_NUM_USES")
		}
		result.VAULT_TOKEN_NUM_USES = int32(n)
	} else {
		result.VAULT_TOKEN_NUM_USES = 0
	}

	ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return result, err
	}
	result.ARGOCD_NAMESPACE = strings.TrimSpace(string(ns))

	return result, nil
}

func SetVaultEnv(vault *vault.Vault, env types.Env, vaultEnv types.VaultEnv) error {
	for _, path := range env.VAULT_ENV_SECRETS {
		envSecrets, err := vault.GetSecrets(vaultEnv.VAULT_TOKEN, fmt.Sprintf("%s/data/%s", env.VAULT_TENANT, path))
		if err != nil {
			return err
		}
		for k, v := range envSecrets {
			os.Setenv(k, v)
		}
	}

	return nil
}

func GetVaultEnv(vault *vault.Vault, env types.Env) (types.VaultEnv, error) {
	result := types.VaultEnv{}

	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return result, err
	}

	vaultAdminToken, err := vault.Login(
		strings.TrimSpace(string(saToken)),
		env.VAULT_AUTH_ROLE,
		env.VAULT_AUTH_METHOD,
	)
	if err != nil {
		return result, err
	}
	result.VAULT_ADMIN_TOKEN = vaultAdminToken

	vaultToken, err := vault.CreateToken(
		vaultAdminToken,
		env.ARGOCD_APP_NAME,
		env.VAULT_POLICIES,
		env.VAULT_TOKEN_TTL,
		env.VAULT_TOKEN_NUM_USES,
	)
	if err != nil {
		return result, err
	}
	result.VAULT_TOKEN = vaultToken

	return result, nil
}

func SetVault(vault *vault.Vault, env types.Env, vaultEnv types.VaultEnv) error {
	var policy string

	for _, path := range env.VAULT_ALLOW_PATHS {
		parts := strings.Split(path, ";")
		if len(parts) != 2 {
			return errors.New("cannot parse vault allow path")
		}

		actions := strings.Split(parts[0], ",")
		for p := range actions {
			actions[p] = strings.TrimSpace(actions[p])
		}

		policy = policy + fmt.Sprintf(`
		path "%s/data/%s" {
		  capabilities = ["%s"]
		}
		`,
			env.VAULT_TENANT,
			parts[1],
			strings.Join(actions, `", "`),
		)
	}

	log.Info("Set vault policies...")
	err := vault.SetPolicy(
		vaultEnv.VAULT_ADMIN_TOKEN,
		env.ARGOCD_APP_NAME,
		policy,
	)
	if err != nil {
		return err
	}

	if env.VAULT_CREATE_KUBERETES_ENGINES {
		log.Info("Create vault kuberentes engines...")
		clusters, err := getClustersSecret(env)
		if err != nil {
			return err
		}

		for _, cluster := range clusters {
			err = vault.EnableKubernetesEngine(vaultEnv.VAULT_ADMIN_TOKEN, cluster)
			if err != nil {
				return err
			}
		}
	}

	if env.VAULT_CREATE_APP_ROLES && env.CLUSTER != "in-cluster" {

		log.Info("Create vault app roles...")
		roles, err := getVaultRoles("rbac/namespace")
		if err != nil {
			return err
		}

		for role, rule := range roles {
			err = vault.CreateKuberentesRole(
				vaultEnv.VAULT_ADMIN_TOKEN,
				env.CLUSTER,
				fmt.Sprintf("%s-%s", env.ARGOCD_APP_NAME, role),
				"Role",
				"24h",
				"168h",
				[]string{env.ARGOCD_APP_NAMESPACE},
				rule,
			)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func Cmd(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return outb.String(), errors.New(errb.String())
	}
	return outb.String(), nil
}

func isNeedRegistry() bool {
	b, err := os.ReadFile("werf.yaml")
	if err != nil {
		return false
	}

	s := string(b)

	return strings.Contains(s, "image:")
}

func parseGitUrl(url string) (string, error) {
	r, err := regexp.Compile(`^(https?|ssh):\/\/([a-zA-Z0-9\.\@\:\-]+)\/(.+).git$`)
	if err != nil {
		log.Panic(err)
	}

	data := r.FindStringSubmatch(url)
	if len(data) != 4 {
		return "", errors.New("cannot parse git url")
	}

	return data[3], nil
}

func getClustersSecret(env types.Env) (result []types.KubernetesClusterSecret, err error) {
	var restConfig *rest.Config

	if path, isSet := os.LookupEnv("KUBECONFIG"); isSet {
		log.Printf("Using configuration from '%s'", path)
		restConfig, err = clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			return
		}
	} else {
		log.Printf("Using in-cluster configuration")
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			return
		}
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return
	}

	opts := metav1.ListOptions{
		LabelSelector: "argocd.argoproj.io/secret-type=cluster",
	}

	secrets, err := clientset.CoreV1().Secrets(env.ARGOCD_NAMESPACE).List(context.Background(), opts)

	for _, secret := range secrets.Items {
		cluster := types.KubernetesClusterSecret{}
		cluster.Name = string(secret.Data["name"])
		cluster.Server = string(secret.Data["server"])

		clusterConfig := types.KubernetesClusterConfig{}
		err = json.Unmarshal(secret.Data["config"], &clusterConfig)
		if err != nil {
			return
		}
		cluster.Config = clusterConfig

		if cluster.Name != "in-cluster" && cluster.Config.BearerToken != "" {
			result = append(result, cluster)
		}
	}

	return
}

func getVaultRoles(path string) (result map[string]string, err error) {
	result = make(map[string]string)

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return
	}

	for _, file := range files {
		if !file.IsDir() {
			data, err := os.ReadFile(fmt.Sprintf("%s/%s", path, file.Name()))
			if err != nil {
				return result, err
			}

			result[strings.Split(file.Name(), ".")[0]] = string(data)
		}

	}

	return
}
