// Copyright (c) Edward Wilde 2018. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package handlers

import (
	"encoding/json"
	"github.com/openfaas/faas/gateway/requests"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

var functions = map[string]*requests.Function{}
// MakeDeployHandler creates a handler to create new functions in the cluster
func MakeDeployHandler(proxy http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Info("deployment request")
		defer r.Body.Close()

		body, _ := ioutil.ReadAll(r.Body)

		request := requests.CreateFunctionRequest{}
		if err := json.Unmarshal(body, &request); err != nil {
			log.Errorln("error during unmarshal of create function request. ", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		proxy.ServeHTTP(w, r)

		log.Infof("deployment request for function %s", request.Service)
	}
}