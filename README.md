# faas-policy-provider

The faas-policy-provider is an implementation of the [faas-provider](https://github.com/openfaas/faas-provider) 
which can be used enforce location and other policy constraints on function execution. Due to being forked from the [faas-federation repository](https://github.com/openfaas-incubator/faas-federation) this provider is located in front of an actual provider – analogous to the original faas-federation provider implementation.

## Why do you need the faas-policy-provider?

With the increasing importance of and interest in the enforcement regulation or different kinds of policies, we oberserved the lack of a tool that can sufficiently and transparently ensure the enforcement of such policies in OpenFaaS deployments. Our implementation aims to provide a basis for services that should be both based on OpenFaaS and be policy compliant – however these policy may be structered and motived.

## Getting started

`faas-federation` can replace your provider in your existing OpenFaaS deployment.

### Local Deployment

The faas-policy provider can be deployed either locally or on an external server. For the local deployment, the following prerequisites have to be fulfilled:

1. Installation of the [faas-cli](https://docs.openfaas.com/cli/install/)
1. install kubectl (e.g. using arkade)
1. e.g. [minikube](https://minikube.sigs.k8s.io/docs/start/)
1. clone this repository

As soon as the previous requirements are fulfilled, execute the following steps:

Minikube: 

1. start minicube `$ minicube start ` 
1. connect to kubectl `$ kubectl get po -A` 
1. open the minikube dashboard (e.g. for getting access to the policy provider's logging) `$ minicube dashboard`

Navigate to the cloned faas-policy-provider:

1. Configure /chart/of-federation/values.yml
1. `$ kubectl apply -f https://raw.githubusercontent.com/openfaas/faas-netes/master/namespaces.yml`
1. `$ kubectl --namespace=default get deployments -l "release=federation, app=openfaas-federation"`
1. `$ helm install federation chart/of-federation/ --values chart/of-federation/values.yaml -n openfaas`

Get the URL of the OpenFaaS UI and check if the instance is running:

1. `$ minikube service -n openfaas gateway-external --url`
1. `$ kubectl --namespace=openfaas get deployments`

Build, push and deploy your function:

`$ faas-cli up -g [YOUR URL HERE] -f [PATH TO YOUR FUNCTION YML]`

### helm chart

See also: example of Kubernetes and AWS Lambda federated configuration in the sample [helm chart](chart/of-federation).

## Gateway routing

To route to one gateway or another, simply set `com.openfaas.federation.gateway` to the name you want to pick.

| Annotation | Description |
| ----|----|
| `com.openfaas.federation.gateway` | route the request based on the provider name i.e. `faas-netes`, `faas-lambda` |

## Configuration

All configuration is managed using environment variables

| Option                            | Usage      | Default                  | Required |
|-----------------------------------|------------|--------------------------|----------|
| `providers`           | comma separated list of provider URLs i.e. `http://faas-netes:8080,http://faas-lambda:8080` | - |   yes    |
| `default_provider`    | default provider URLs used when no deployment constraints are matched i.e. `http://faas-netes:8080` | - |   yes    |

## Acknowledgements

Source forked from `faas-federation`.

## License

MIT
