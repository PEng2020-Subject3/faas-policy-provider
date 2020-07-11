package handlers

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"bytes"
	"errors"
	"io/ioutil"
	"encoding/json"

	"github.com/gorilla/mux"

	ftypes "github.com/openfaas/faas-provider/types"
	"github.com/PEng2020-Subject3/faas-policy-provider/types"
	"github.com/PEng2020-Subject3/faas-policy-provider/routing"
	log "github.com/sirupsen/logrus"
)

const (
	watchdogPort           	= "8080"
	defaultContentType     	= "text/plain"
	errMissingFunctionName 	= "Please provide a valid route /function/function_name."
	urlScheme 							= "http"
)

// MakeProxyHandler creates a handler to invoke functions downstream
func MakeProxyHandler(proxy http.HandlerFunc, providerLookup routing.ProviderLookup, policyController types.PolicyController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Info("proxy request")

		pathVars := mux.Vars(r)
		if pathVars == nil {
			r = mux.SetURLVars(r, map[string]string{})
			pathVars = mux.Vars(r)
		}

		functionName := strings.Split(r.URL.Path, "/")[2]
		oldFunctionName := functionName

		// Policy Managment
		query := r.URL.Query()

		policy, ok := query["policy"]
		if ok && len(policy) == 1 {
			policyName := policy[0]
			log.Infof("request for function: %s", functionName)
			log.Infof("request for policy: %s", policyName)

			if _, ok := policyController.GetPolicy(policyName); !ok {
				log.Infof("error during function request. Policy %s not found", policyName)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			
			policyFunctionName, err := policyProxy(w, r, functionName, policyName, 
				providerLookup, policyController)
			
			if err != nil {
				log.Errorln("error during function request. ", err.Error())
				w.WriteHeader(http.StatusNotFound)
				return
			}

			functionName = policyFunctionName

		} else {
			log.Info("no policy defined")
		}

		pathVars["name"] = functionName
		pathVars["params"] = strings.Replace(r.URL.Path, oldFunctionName, functionName, -1)
		proxy.ServeHTTP(w, r)

		log.Info(pathVars)

		log.Infof("proxy request for function %s path %s", functionName, r.URL.String())
	}
}

// FunctionLookup is a openfaas-provider proxy.BaseURLResolver that allows the
// caller to verify that a function is resolvable.
type FunctionLookup struct {
	// scheme is the http scheme (http/https) used to proxy the request
	scheme string
	// dnsrrLookup method used to resolve the function IP address, defaults to the internal lookupIP
	// method, which is an implementation of net.LookupIP
	dnsrrLookup    func(context.Context, string) ([]net.IP, error)
	providerLookup routing.ProviderLookup
}

func policyProxy(w http.ResponseWriter, r *http.Request, functionName string, policy string, 
	providerLookup routing.ProviderLookup, policyController types.PolicyController) (string, error) {

	log.Infof("resolve policy function %s", functionName)
	_, policyFunctionName, err := policyController.GetPolicyFunction(functionName, policy)
	if err != nil {		
		log.Infof("function %s with policy %s not found", functionName, policy) 

		deployment, ok := providerLookup.GetFunction(functionName)					
		if !ok {
			log.Errorf("error for provider resolving function %s.", functionName)
			return "", errors.New("error for provider resolving function: " + functionName)
		}

		url, err := providerLookup.Resolve(functionName)
		if err != nil {
			log.Errorf("error for provider resolving function %s.", functionName)
			return "", err
		}

		log.Infof("deployment %s found", deployment.Service)
		deployment, policyFunction := policyController.BuildDeployment(&types.PolicyFunction{Policy: policy}, deployment)	
		depErr := policyDeploy(w, r, url, deployment)
		if depErr != nil {
			log.Errorf("polic deploy failed for %s with %s.", deployment.Service, depErr)
			return "", depErr
		}
		policyController.AddPolicyFunction(functionName, *policyFunction)
		//providerLookup.AddFunction(deployment)
		policyFunctionName = deployment.Service
	
	}
	return policyFunctionName, nil
}

func policyDeploy(w http.ResponseWriter, originalReq *http.Request, baseURL *url.URL, deployment *ftypes.FunctionDeployment) error {
	ctx := originalReq.Context()

	json, err := json.Marshal(deployment)
	if err != nil {
		return err
	}

	upstreamReq, err := buildProxyRequest(originalReq, *baseURL, "/system/functions")
	if err != nil {
		return err
	}
	if upstreamReq.Body != nil {
		defer upstreamReq.Body.Close()
	}

	upstreamReq.Method = "POST"
	upstreamReq.Body = ioutil.NopCloser(bytes.NewReader(json))
	upstreamReq.Header.Set("Content-Type", "application/json; charset=UTF-8")
	log.Info(upstreamReq)

	client := &http.Client{}
	resp, err := client.Do(upstreamReq.WithContext(ctx))
	if err != nil {
		log.Printf("error with policy deploy request to: %s, %s\n", upstreamReq.URL.String(), err.Error())
		return err
	}

	log.Info("response Status: ", resp.Status)
	defer resp.Body.Close()		

	// poll for deployed function	
	q := originalReq.URL.Query()
  q.Del("policy")
  originalReq.URL.RawQuery = q.Encode()
	pollReq, err := buildProxyRequest(originalReq, *baseURL, "/function/" + deployment.Service)
	if err != nil {
		return err
	}

	start := time.Now()
	for {		
		log.Info("polling for newly deployed function: " + pollReq.URL.String())
		resp, err := client.Do(pollReq.WithContext(ctx))
		if err != nil {
			log.Printf("error plling after policy deploy request to: %s, %s\n", pollReq.URL.String(), err.Error())
			return err
		}
		if resp.StatusCode == 200 {
			break
		}
		time.Sleep(time.Second)
	}
	elapsed := time.Since(start)
	log.Infof("PERFORMANCE: polling took %s", elapsed)	
	return nil
}

// NewFunctionLookup creates a new FunctionLookup resolver
func NewFunctionLookup(providerLookup routing.ProviderLookup) *FunctionLookup {
	return &FunctionLookup{
		scheme:         urlScheme,
		dnsrrLookup:    lookupIP,
		providerLookup: providerLookup,
	}
}

// Resolve implements the openfaas-provider proxy.BaseURLResolver interface.
func (l *FunctionLookup) Resolve(name string) (u url.URL, err error) {
	log.Infof("resolving function %s", name)
	providerURL, err := l.providerLookup.Resolve(name)
	if err != nil {
		return url.URL{}, err
	}

	log.Infof("using provider %s to for function %s", providerURL.String(), name)

	return *providerURL, nil
}

// resolve the function by checking the available docker DNSRR resolution
func (l *FunctionLookup) byDNSRoundRobin(ctx context.Context, name string) (string, error) {
	entries, lookupErr := l.dnsrrLookup(ctx, fmt.Sprintf("tasks.%s", name))

	if lookupErr != nil {
		return "", lookupErr
	}

	if len(entries) > 0 {
		index := randomInt(0, len(entries))
		return entries[index].String(), nil
	}

	return "", fmt.Errorf("could not resolve '%s' using dnsrr", name)
}

func randomInt(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}

// lookupIP implements the net.LookupIP method with context support. It returns a slice of that\
// host's IPv4 and IPv6 addresses.
func lookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, ia := range addrs {
		ips[i] = ia.IP
	}
	return ips, nil
}

func buildProxyRequest(originalReq *http.Request, baseURL url.URL, extraPath string) (*http.Request, error) {
	log.Infof("build proxy request with %s for %s", baseURL.String(), extraPath)

	host := baseURL.Host

	url := url.URL{
		Scheme:   urlScheme,
		Host:     host,
		Path:     extraPath,
		RawQuery: originalReq.URL.RawQuery,
	}

	upstreamReq, err := http.NewRequest(originalReq.Method, url.String(), nil)
	if err != nil {
		return nil, err
	}
	copyHeaders(upstreamReq.Header, &originalReq.Header)

	if len(originalReq.Host) > 0 && upstreamReq.Header.Get("X-Forwarded-Host") == "" {
		upstreamReq.Header["X-Forwarded-Host"] = []string{originalReq.Host}
	}
	if upstreamReq.Header.Get("X-Forwarded-For") == "" {
		upstreamReq.Header["X-Forwarded-For"] = []string{originalReq.RemoteAddr}
	}

	if originalReq.Body != nil {
		upstreamReq.Body = originalReq.Body
	}

	return upstreamReq, nil
}

// copyHeaders clones the header values from the source into the destination.
func copyHeaders(destination http.Header, source *http.Header) {
	for k, v := range *source {
		vClone := make([]string, len(v))
		copy(vClone, v)
		destination[k] = vClone
	}
}

// getContentType resolves the correct Content-Type for a proxied function.
func getContentType(request http.Header, proxyResponse http.Header) (headerContentType string) {
	responseHeader := proxyResponse.Get("Content-Type")
	requestHeader := request.Get("Content-Type")

	if len(responseHeader) > 0 {
		headerContentType = responseHeader
	} else if len(requestHeader) > 0 {
		headerContentType = requestHeader
	} else {
		headerContentType = defaultContentType
	}

	return headerContentType
}