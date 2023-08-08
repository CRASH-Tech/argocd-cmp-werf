package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func createSaToken(app, duration string) (string, error) {
	out, err := Cmd(fmt.Sprintf("kubectl create token %s --duration %s", app, duration))
	if err != nil {
		return "", err
	}

	return out, err
}

func createVaultAuthRole(vault *vault.Vault, adminToken, name, mount string, saNames, NSs, policies []string) error {
	err := vault.CreateAuthRoleKubernetes(
		adminToken,
		name,
		mount,
		saNames,
		NSs,
		policies,
		VAULT_TOKEN_TTL,
	)

	return err
}

func getVaultAuthToken(vault *vault.Vault, saToken, role, mountPath string) (token, entityId string, err error) {
	token, entityId, err = vault.Login(
		saToken,
		role,
		mountPath,
	)

	return
}

func createVaultPolicy(vault *vault.Vault, adminToken, name, tenant string, paths []string) error {
	var policy string

	for _, path := range paths {
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
			tenant,
			parts[1],
			strings.Join(actions, `", "`),
		)
	}

	err := vault.SetPolicy(
		adminToken,
		name,
		policy,
	)

	return err
}

func createVaultAuthEntity(vault *vault.Vault, adminToken, appEntityId, name string, policies []string, metadata map[string]interface{}) error {
	err := vault.SetEntity(
		adminToken,
		appEntityId,
		name,
		policies,
		metadata,
	)
	if err != nil {
		return err
	}

	return nil
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

func isNeedRegistry() bool {
	b, err := os.ReadFile("werf.yaml")
	if err != nil {
		log.Panic(err)
	}

	s := string(b)

	return strings.Contains(s, "image:")
}

func setEnv(init bool) {
	//REMOVE ARGOCD_ENV_ PREFIX
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		os.Setenv(strings.TrimPrefix(pair[0], "ARGOCD_ENV_"), pair[1])
	}

	//SET VARS
	ARGOCD_APP_NAME = os.Getenv("ARGOCD_APP_NAME")
	ARGOCD_APP_SOURCE_REPO_URL = os.Getenv("ARGOCD_APP_SOURCE_REPO_URL")
	PROJECT = os.Getenv("PROJECT")
	ENV = os.Getenv("ENV")
	APP = os.Getenv("APP")
	INSTANCE = os.Getenv("INSTANCE")
	if ttl, isSet := os.LookupEnv("VAULT_TOKEN_TTL"); isSet {
		ttl, err := strconv.Atoi(ttl)
		if err != nil {
			log.Panic("cannot parse VAULT_TOKEN_TTL")
		}
		VAULT_TOKEN_TTL = int32(ttl)
	} else {
		VAULT_TOKEN_TTL = 3600
	}

	//GET CURRENT NS
	ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Panic(err)
	}
	ARGOCD_NAMESPACE = strings.TrimSpace(string(ns))

	//SET VAULT VARS
	if os.Getenv("VAULT_ENABLED") == "true" {
		VAULT_ENABLED = true
		VAULT_ADDR = os.Getenv("VAULT_ADDR")
		VAULT_ADMIN_ROLE = os.Getenv("VAULT_ADMIN_ROLE")
		VAULT_ADMIN_SA = os.Getenv("VAULT_ADMIN_SA")
		VAULT_AUTH_METHOD = os.Getenv("VAULT_AUTH_METHOD")
		VAULT_TENANT = os.Getenv("VAULT_TENANT")
		WERF_CACHE_DISABLED = (os.Getenv("WERF_CACHE_DISABLED") == "true")
		VAULT_CREATE_KUBERETES_ENGINES = (os.Getenv("VAULT_CREATE_KUBERETES_ENGINES") == "true")

		VAULT_POLICIES = append(VAULT_POLICIES, ARGOCD_APP_NAME)
		for _, e := range os.Environ() {
			pair := strings.SplitN(e, "=", 2)
			if strings.HasPrefix(pair[0], "VAULT_POLICY_") {
				VAULT_POLICIES = append(VAULT_POLICIES, pair[1])
			}
			if strings.HasPrefix(pair[0], "VAULT_ALLOW_PATH_") {
				VAULT_ALLOW_PATHS = append(VAULT_ALLOW_PATHS, pair[1])
			}
			if strings.HasPrefix(pair[0], "VAULT_ENV_SECRETS_") {
				VAULT_ENV_SECRETS = append(VAULT_ENV_SECRETS, pair[1])
			}
		}

		vault, err := vault.New(VAULT_ADDR)
		if err != nil {
			log.Panic(err)
		}

		///SET VAULT RULES
		if init {
			tokens, err := getTokens(vault)
			if err != nil {
				log.Panic(err)
			}
			VAULT_APP_TOKEN = tokens.VaultAppToken

			setVaultRules(vault, tokens)

			//CREATE KUBERETES ENGINES
			if VAULT_CREATE_KUBERETES_ENGINES {
				createVaultKuberentesEngines(vault, tokens)
			}
		}

		//GET APP SA TOKEN
		saAppToken, err := createSaToken(ARGOCD_APP_NAME, "1h")
		if err != nil {
			log.Panic(err)
		}

		//GET VAULT APP TOKEN
		appToken, _, err := getVaultAuthToken(vault, saAppToken, ARGOCD_APP_NAME, VAULT_AUTH_METHOD)
		if err != nil {
			log.Panic(err)
		}
		VAULT_APP_TOKEN = appToken

		//GET VAULT SECRETS
		for _, path := range VAULT_ENV_SECRETS {
			envSecrets, err := vault.GetSecrets(VAULT_APP_TOKEN, fmt.Sprintf("%s/data/%s", VAULT_TENANT, path))
			if err != nil {
				log.Panic(err)
			}
			for k, v := range envSecrets {
				os.Setenv(k, v)
			}
		}

		///SET REGISTRY VARS
		if isNeedRegistry() {
			gitPath, err := parseGitUrl(ARGOCD_APP_SOURCE_REPO_URL)
			if err != nil {
				log.Panic(err)
			}
			os.Setenv("DOCKER_CONFIG", fmt.Sprintf("/tmp/%s", ARGOCD_APP_NAME))

			if WERF_CACHE_DISABLED {
				os.Setenv("WERF_REPO", fmt.Sprintf("%s/%s/%s", os.Getenv("REGISTRY"), PROJECT, gitPath))
			} else {
				os.Setenv("WERF_REPO", fmt.Sprintf("%s/%s/cache", os.Getenv("REGISTRY"), PROJECT))
				os.Setenv("WERF_FINAL_REPO", fmt.Sprintf("%s/%s/%s", os.Getenv("REGISTRY"), PROJECT, gitPath))
			}
		}
	}
}

func getTokens(vault *vault.Vault) (result types.VaultTokens, err error) {
	log.Info("Create admin SA token...")
	saAdminToken, err := createSaToken(VAULT_ADMIN_SA, "1h")
	if err != nil {
		return
	}
	result.SaAdminToken = saAdminToken

	log.Info("Get vault admin token...")
	vaultAdminToken, _, err := getVaultAuthToken(vault, saAdminToken, VAULT_ADMIN_ROLE, VAULT_AUTH_METHOD)
	if err != nil {
		return
	}
	result.VaultAdminToken = vaultAdminToken

	log.Info("Get app SA token...")
	saAppToken, err := createSaToken(ARGOCD_APP_NAME, "1h")
	if err != nil {
		return
	}
	result.SaAppToken = saAppToken

	log.Info("Get app vault token...")
	vaultAppToken, vaultAppEntityId, err := getVaultAuthToken(vault, saAppToken, ARGOCD_APP_NAME, VAULT_AUTH_METHOD)
	if err != nil {
		return
	}
	result.VaultAppToken = vaultAppToken
	result.AppEntityId = vaultAppEntityId

	return
}

func setVaultRules(vault *vault.Vault, tokens types.VaultTokens) {
	log.Info("Set vault rules...")

	log.Info("Create vault app policy...")
	err := createVaultPolicy(vault, tokens.VaultAdminToken, ARGOCD_APP_NAME, VAULT_TENANT, VAULT_ALLOW_PATHS)
	if err != nil {
		log.Panic(err)
	}

	log.Info("Create vault app auth role...")
	err = createVaultAuthRole(vault, tokens.VaultAdminToken, ARGOCD_APP_NAME, VAULT_AUTH_METHOD,
		[]string{ARGOCD_APP_NAME},
		[]string{ARGOCD_NAMESPACE},
		VAULT_POLICIES,
	)
	if err != nil {
		log.Panic(err)
	}

	log.Info("Create vault app entity...")
	metadata := map[string]interface{}{
		"project":  PROJECT,
		"env":      ENV,
		"app":      APP,
		"instance": INSTANCE,
	}

	err = createVaultAuthEntity(vault, tokens.VaultAdminToken, tokens.AppEntityId, ARGOCD_APP_NAME, VAULT_POLICIES, metadata)
	if err != nil {
		log.Panic(err)
	}
}

func getClustersSecret() (result []types.KubernetesClusterSecret, err error) {
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

	secrets, err := clientset.CoreV1().Secrets(ARGOCD_NAMESPACE).List(context.Background(), opts)

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

		if cluster.Name != "in-cluster" {
			result = append(result, cluster)
		}
	}

	return
}

func createVaultKuberentesEngines(vault *vault.Vault, tokens types.VaultTokens) {
	log.Info("Create vault kuberentes engines...")
	clusters, err := getClustersSecret()
	if err != nil {
		log.Panic(err)
	}
	for _, cluster := range clusters {
		err = vault.EnableKubernetesEngine(tokens.VaultAdminToken, cluster)
		if err != nil {
			log.Panic(err)
		}
	}
}
