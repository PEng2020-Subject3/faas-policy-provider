# faas-policy-provider

The `faas-policy-provider` is an implementation of the [faas-provider](https://github.com/openfaas/faas-provider),
which can be used enforce location and other policy constraints on function execution.
Due to being forked from the [faas-federation](https://github.com/openfaas-incubator/faas-federation) repository this 
provider is located in front of an actual provider – analogous to the original faas-federation provider implementation.

## Why do you need the faas-policy-provider?

With the increasing importance of and interest in the enforcement of regulations or different kinds of policies, we observed
the lack of a tool that can sufficiently and transparently ensure the enforcement of such policies in OpenFaaS deployments. 
Our implementation aims to provide a basis for services that should be both based on OpenFaaS and be policy compliant – 
however these policies may be structured and motivated.

## Getting started

`faas-policy-provider` can replace your provider in your existing OpenFaaS deployment.

OpenFaas can be deployed either locally or on an external server. Either way, the following 
prerequisites have to be fulfilled:

1. install [faas-cli](https://docs.openfaas.com/cli/install/)
2. install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
3. install [helm](https://helm.sh/docs/intro/install/)
4. clone this repository
5. install a tool to create a kubernetes cluster (e.g. [minikube](https://minikube.sigs.k8s.io/docs/start/)) or 
   use a remote cluster (e.g. from a service provider).

The following section explains how to create a kubernetes cluster on your local machine with minikube.

### Setup a kubernetes cluster with Minikube 

```bash
# 0. (optional) set the virtualization driver to your liking - see https://minikube.sigs.k8s.io/docs/drivers/
minikube config set driver docker

# 1. start minikube
minikube start

# 2. Verify that kubectl is configured to run with minikube
kubectl get po -A

# 3. open the minikube dashboard (e.g. for a visual overview of the clusters deployments and services)
minikube dashboard
```

### Install OpenFaas with the faas-policy-provider

Navigate to the cloned faas-policy-provider directory:

```bash
# 0. Configure `chart/of-federation/values.yml` if needed.
# 1. Add kubernetes namespaces openfaas and openfaas-fn
kubectl apply -f https://raw.githubusercontent.com/openfaas/faas-netes/master/namespaces.yml
# 2. create a password
PASSWORD=$(head -c 12 /dev/urandom | shasum | cut -d' ' -f1)
# 3. add the authentication secret to kubernetes
kubectl -n openfaas create secret generic basic-auth \
--from-literal=basic-auth-user=admin \
--from-literal=basic-auth-password=$PASSWORD
# 4. install openfaas with the faas-policy-provider via helm. For a non-local installation add `--set serviceType=LoadBalancer`
helm install openfaas-policy chart/of-federation/ --values chart/of-federation/values.yaml -n openfaas
# 5. verify installation
kubectl --namespace=openfaas get deployments -l "release=openfaas-policy, app=openfaas-federation"
```

To retrieve the password for logging into the openfaas-ui portal, run `echo $PASSWORD` or
view the secret in the kubernetes dashboard.

Get the URL of the OpenFaaS UI and check if the instance is running:

- With minikube: `minikube service -n openfaas gateway-external --url`
- In an installation with a loadbalancer see the external ip in `kubectl --namespace=openfaas get svc`

Deploy your function via the OpenFaas-UI portal or with `faas-cli deploy -g [YOUR GATEWAY URL HERE] -f [PATH TO YOUR FUNCTION YML]`

To update the configuration of the faas-policy-provider:

`helm upgrade federation chart/of-federation/ --values chart/of-federation/values.yaml -n openfaas`

### Drop-in replacement of an existing OpenFaas installation

If you already have an openfaas installation managed by helm, you can upgrade the revision with the faas-policy-provider
configuration. Bed careful though, compare the set values and set them accordingly if necessary.

If this won't work for any reason, deleting the OpenFaas installation 
(with the name `openfaas` in this example: `helm uninstall openfaas --keep-history -n openfaas`)
and installing the helm chart of faas-policy-provider as above should definitely work.

No deployed function will be hurt in this process.

## Configuration

### Policies

The configuration is currently done via the `values.yaml` and defined on the deployment of the faas-policy-provider.

Examples:

```yaml
policies:
  - name: test
    environment:
      openfaas.policy.name: test
  - name: gdpr
    environment:
      openfaas.policy.name: gdpr
    constraints:
        - "failure-domain.beta.kubernetes.io/region=us-east-1"
        - "openfaas.policy/privacy-level=1"
  - name: restricted
    readonly_root_filesystem: true
    environment:
      openfaas.policy.name: restricted
      db_host: usecase-db-restricted-postgresql
      db_password: ngvc8dXsVP
    constraints:
      - "openfaas.policy/privacy-level=3"
``` 

There are several options of a function configuration that can be added with a policy specification, 
especially in context with the kubernetes provider.  
The following parts of a function configuration can be overridden or merged with those of a policy specification:
- [annotations](https://docs.openfaas.com/reference/yaml/#function-annotations)
- [environment variables](https://docs.openfaas.com/reference/yaml/#function-environmental-variables)
- [labels](https://docs.openfaas.com/reference/yaml/#function-labels)
- [constraints](https://docs.openfaas.com/reference/yaml/#function-constraints)
- [secrets](https://docs.openfaas.com/reference/yaml/#function-secure-secrets)
- [limits](https://docs.openfaas.com/reference/yaml/#function-memorycpu-limits)
- [readonly filesystem](https://docs.openfaas.com/reference/yaml/#function-read-only-root-filesystem)

For constraining the location for the deployment of a function, you have to utilize the [constraints](https://docs.openfaas.com/reference/yaml/#function-constraints)
directive. Handling of these constraints may differ between the underlying orchestrators.  
For Kubernetes this translates to the [NodeSelectors](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/)
which for example limit the available nodes for a policy based on labels, that mark a node as compliant to that policy.

### Faas Federation

Since this work is based on [faas-federation](https://github.com/openfaas-incubator/faas-federation), it can still be
configured as such. For multiple providers it will probably be very useful to use policy constraints to constraint which
provider will serve which request.  
Though the policy-provider functionality was not tested with multiple providers, yet. 

All configuration is managed using environment variables:

| Option                            | Usage      | Default                  | Required |
|-----------------------------------|------------|--------------------------|----------|
| `providers`           | comma separated list of provider URLs i.e. `http://faas-netes:8080,http://faas-lambda:8080` | - |   yes    |
| `default_provider`    | default provider URLs used when no deployment constraints are matched i.e. `http://faas-netes:8080` | - |   yes    |

#### Gateway routing

To route to one gateway or another, simply set `com.openfaas.federation.gateway` to the name you want to pick.

| Annotation | Description |
| ----|----|
| `com.openfaas.federation.gateway` | route the request based on the provider name i.e. `faas-netes`, `faas-lambda` |

## Acknowledgements

The project is forked from and based on [faas-federation](https://github.com/openfaas-incubator/faas-federation).

## License

MIT
