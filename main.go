package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/PEng2020-Subject3/faas-policy-provider/handlers"
	"github.com/PEng2020-Subject3/faas-policy-provider/routing"
	"github.com/PEng2020-Subject3/faas-policy-provider/types"
	"github.com/PEng2020-Subject3/faas-policy-provider/version"
	bootstrap "github.com/openfaas/faas-provider"
	"github.com/openfaas/faas-provider/proxy"

	bootTypes "github.com/openfaas/faas-provider/types"
	log "github.com/sirupsen/logrus"
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

	policyStore := types.PolicyStore{}
	policyStore.AddPolicy(types.Policy{"GDPR", []string{"region:eu"}})
	policyStore.AddPolicyFunction("test", "GDPR", types.PolicyFunction{"test-GDPR", []string{"GDPR"}, ""})

	bootstrapHandlers := bootTypes.FaaSHandlers{
		FunctionProxy:  handlers.MakeProxyHandler(proxyFunc, policyStore),
		DeleteHandler:  handlers.MakeDeleteHandler(proxyFunc),
		DeployHandler:  handlers.MakeDeployHandler(proxyFunc, providerLookup),
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
