package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PEng2020-Subject3/faas-policy-provider/routing"
	acc "github.com/PEng2020-Subject3/faas-policy-provider/testing"
	"github.com/gorilla/mux"
	"github.com/openfaas/faas-provider/proxy"
	"github.com/openfaas/faas-provider/types"
)

func Test_Invoke(t *testing.T) {
	acc.PreCheckAcc(t)
	req, err := http.NewRequest("POST", "/function/echo-b", bytes.NewBuffer([]byte("Hello World")))
	req.Header.Add("Content-Type", "text/plain")
	if err != nil {
		t.Fatal(err)
	}

	mux.NewRouter()
	rr := httptest.NewRecorder()

	providerLookup, err := routing.NewDefaultProviderRouting([]string{"http://faas-provider-a:8082", "http://faas-provider-b:8083"}, "http://faas-provider-a:8082")
	if err != nil {
		t.Fatal(err)
	}

	config := types.FaaSConfig{ReadTimeout: time.Minute * 1}
	proxyFunc := proxy.NewHandlerFunc(config, NewFunctionLookup(providerLookup))
	MakeProxyHandler(proxyFunc).ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
