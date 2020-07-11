package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PEng2020-Subject3/faas-policy-provider/routing"
	acc "github.com/PEng2020-Subject3/faas-policy-provider/testing"
	policy "github.com/PEng2020-Subject3/faas-policy-provider/types"
	"github.com/gorilla/mux"
	"github.com/openfaas/faas-provider/proxy"
	"github.com/openfaas/faas-provider/types"
)

// Test_Delete requires `make up` and `cd examples && faas-cli up`
func Test_Delete(t *testing.T) {
	acc.PreCheckAcc(t)
	req, err := http.NewRequest("DELETE", "/system/functions", bytes.NewBuffer([]byte(echoDelete)))
	if err != nil {
		t.Fatal(err)
	}

	mux.NewRouter()
	rr := httptest.NewRecorder()

	providerLookup, err := routing.NewDefaultProviderRouting([]string{"http://faas-provider-a:8082", "http://faas-provider-b:8083"}, "http://faas-provider-a:8082")
	if err != nil {
		t.Fatal(err)
	}

	err = providerLookup.ReloadCache()
	if err != nil {
		t.Fatalf("error reloading provider cache. %v", err)
	}
	policyStore := new(policy.PolicyStore)
	config := types.FaaSConfig{ReadTimeout: time.Minute * 1}
	proxyFunc := proxy.NewHandlerFunc(config, NewFunctionLookup(providerLookup))

	MakeDeleteHandler(proxyFunc, providerLookup, policyStore).ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

const echoDelete = `{"functionName":"echo-b"}`
