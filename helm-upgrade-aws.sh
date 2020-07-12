#!/usr/bin/env bash
helm upgrade federation chart/of-federation/ --values chart/of-federation/values.yaml -n openfaas --set serviceType=LoadBalancer