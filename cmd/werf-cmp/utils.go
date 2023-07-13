package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
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

func createAppToken(app, duration string) (string, error) {
	out, err := Cmd(fmt.Sprintf("kubectl create token %s --duration %s", app, duration))
	if err != nil {
		return "", err
	}

	return out, err
}

func getEnv() {
	log.Info("Get env...")
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		os.Setenv(strings.TrimPrefix(pair[0], "ARGOCD_ENV_"), pair[1])
	}

	VAULT_ENABLED = (os.Getenv("VAULT_ENABLED") == "true")

	VAULT_ADDR = os.Getenv("VAULT_ADDR")
	VAULT_ADMIN_ROLE = os.Getenv("VAULT_ADMIN_ROLE")
	VAULT_AUTH_METHOD = os.Getenv("VAULT_AUTH_METHOD")
	ARGOCD_APP_NAME = os.Getenv("ARGOCD_APP_NAME")

	PROJECT = os.Getenv("PROJECT")
	ENV = os.Getenv("ENV")
	APP = os.Getenv("APP")
	INSTANCE = os.Getenv("INSTANCE")

	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if strings.HasPrefix(pair[0], "VAULT_POLICY_") {
			VAULT_POLICIES = append(VAULT_POLICIES, pair[1])
		}
		if strings.HasPrefix(pair[0], "VAULT_ALLOW_PATH_") {
			VAULT_ALLOW_PATHS = append(VAULT_ALLOW_PATHS, pair[1])
		}
	}

	log.Info("Get current namespace...")
	ns, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Panic(err)
	}
	ARGOCD_NAMESPACE = string(ns)
}
