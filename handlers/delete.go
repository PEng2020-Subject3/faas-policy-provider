// Copyright (c) Edward Wilde 2018. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package handlers

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/openfaas/faas/gateway/requests"
	log "github.com/sirupsen/logrus"
)

// MakeDeleteHandler delete a function
func MakeDeleteHandler(proxy http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info("delete request")
		defer r.Body.Close()

		body, _ := ioutil.ReadAll(r.Body)
		request := requests.DeleteFunctionRequest{}
		if err := json.Unmarshal(body, &request); err != nil {
			log.Errorln(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if len(request.FunctionName) == 0 {
			log.Errorln("can not delete a function, request function name is empty")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		pathVars := mux.Vars(r)
		if pathVars == nil {
			r = mux.SetURLVars(r, map[string]string{})
			pathVars = mux.Vars(r)
		}

		pathVars["name"] = request.FunctionName
		pathVars["params"] = r.URL.Path
		proxy.ServeHTTP(w, r)

		log.Infof("delete request %s successful", request.FunctionName)
	}
}
