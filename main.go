package main

import (
	"fmt"
	"os"
	"strings"

	b64 "encoding/base64"

	"github.com/PEng2020-Subject3/faas-policy-provider/handlers"
	"github.com/PEng2020-Subject3/faas-policy-provider/routing"
	"github.com/PEng2020-Subject3/faas-policy-provider/types"
	"github.com/PEng2020-Subject3/faas-policy-provider/version"
	bootstrap "github.com/openfaas/faas-provider"
	"github.com/openfaas/faas-provider/proxy"

	bootTypes "github.com/openfaas/faas-provider/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func init() {
	logFormat := os.Getenv("LOG_FORMAT")
	logLevel := os.Getenv("LOG_LEVEL")
	if strings.EqualFold(logFormat, "json") {
		log.SetFormatter(&log.JSONFormatter{
			FieldMap: log.FieldMap{
				log.FieldKeyMsg:  "message",
				log.FieldKeyTime: "@timestamp",
			},
			TimestampFormat: "2006-01-02T15:04:05.999Z07:00",
		})
	} else {
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp: true,
		})
	}

	if level, err := log.ParseLevel(logLevel); err == nil {
		log.SetLevel(level)
	}
}

func main() {
	// enable debug logging for now
	log.SetLevel(log.DebugLevel)

	log.Infof("faas-policy-provider version: %s. Last commit message: %s, commit SHA: %s", version.BuildVersion(), version.GitCommitMessage, version.GitCommitSHA)

	readConfig := types.ReadConfig{}
	osEnv := types.OsEnv{}
	cfg, err := readConfig.Read(osEnv)
	if err != nil {
		panic(fmt.Errorf("could not read provider config, error: %v", err))
	}

	providerLookup, err := routing.NewDefaultProviderRouting(cfg.Providers, cfg.DefaultProvider)
	if err != nil {
		panic(fmt.Errorf("could not create provider lookup, error: %v", err))
	}

	err = providerLookup.ReloadCache()
	if err != nil {
		panic(fmt.Errorf("could not reload provider cache, error: %v", err))
	}

	proxyFunc := proxy.NewHandlerFunc(cfg.FaaSConfig,
		handlers.NewFunctionLookup(providerLookup))

	/*data := `
	  - name: gdpr
	    constraints:
	        - "topology.kubernetes.io/region=us-east-1"
	  - name: restricted
	    readonly_root_filesystem: true
	    environment:
		      db_host: usecase-db-restricted-postgresql
		      db_password: ngvc8dXsVP
	    constraints:
	        - "openfaas.policy/privacy-level=3"
	        - "node.kubernetes.io/instance-type=m3.medium"`*/

	var out []types.Policy
	sDec, _ := b64.StdEncoding.DecodeString(osEnv.Getenv("policies"))
	err = yaml.Unmarshal([]byte(sDec), &out)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	log.Infof("--- t:\n%v\n\n", out)

	policyStore := types.NewPolicyStore()
	policyStore.AddPolicies(out)
	policyStore.ReloadFromCache(providerLookup.GetFunctions())

	bootstrapHandlers := bootTypes.FaaSHandlers{
		FunctionProxy:  handlers.MakeProxyHandler(proxyFunc, providerLookup, policyStore),
		DeleteHandler:  handlers.MakeDeleteHandler(proxyFunc, providerLookup, policyStore),
		DeployHandler:  handlers.MakeDeployHandler(proxyFunc, providerLookup, policyStore),
		FunctionReader: handlers.MakeFunctionReader(cfg.Providers),
		ReplicaReader:  handlers.MakeReplicaReader(),
		ReplicaUpdater: handlers.MakeReplicaUpdater(),
		UpdateHandler:  handlers.MakeUpdateHandler(proxyFunc, providerLookup),
		HealthHandler:  handlers.MakeHealthHandler(),
		InfoHandler:    handlers.MakeInfoHandler(version.BuildVersion(), version.GitCommitSHA),
	}

	bootstrapConfig := bootTypes.FaaSConfig{
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		TCPPort:         &cfg.Port,
		EnableHealth:    true,
		EnableBasicAuth: false,
	}

	log.Infof("listening on port %d", cfg.Port)
	bootstrap.Serve(&bootstrapHandlers, &bootstrapConfig)
}
