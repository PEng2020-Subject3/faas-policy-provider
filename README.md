faas-policy-provider
-----

faas-policy-provider is an implementation of the [faas-provider](https://github.com/openfaas/faas-provider) 
which can be used enforce location and other policy constraints on function execution.  
Similar to [faas-federation](https://github.com/openfaas-incubator/faas-federation) this provider is set in front of an
actual provider.

## Why do we need this?


## Getting started

`faas-federation` can replace your provider in your existing OpenFaaS deployment.

More coming soon.

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
