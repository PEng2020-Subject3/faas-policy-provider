// Package types contains definitions for public types
package types

import(
	"sync"
	bootTypes "github.com/openfaas/faas-provider/types"
)

type Policy struct {
	Name 										string `yaml:"name"`
	EnvVars 								*map[string]string `yaml:"environment"`
	Constraints 						*[]string `yaml:"constraints"`
	Secrets 								*[]string `yaml:"secrets"`
	Labels 									*map[string]string `yaml:"labels"`
	Annotations 						*map[string]string `yaml:"annotations"`
	Limits 									*FunctionResources `yaml:"limits"`
	Requests 								*FunctionResources `yaml:"requests"`
	ReadOnlyRootFilesystem 	*bool `yaml:"readOnlyRootFilesystem"`
	Namespace 							*string `yaml:"namespace,omitempty"`
}

type FunctionResources struct {
	Memory string `yaml:"memory"`
	CPU    string `yaml:"cpu"`
}

type PolicyFunction struct {
	InternalName 	string
	Policy				string
}

type PolicyController interface {
	GetPolicyFunction(functionName string, policyName string) (string, error)
	// Return added function name
	AddPolicyFunction(lookUpName string, function PolicyFunction) string
	AddPolicy(policy Policy) string
	AddPolicies(policies []Policy)
	BuildDeploymentForPolicy(function PolicyFunction, deployment *bootTypes.FunctionDeployment) bootTypes.FunctionDeployment
}

type PolicyStore struct {
	lookUp 		map[string][]PolicyFunction
	policies 	map[string]Policy
	lock 			sync.RWMutex
}

func NewPolicyStore() *PolicyStore {
	return &PolicyStore{
		lookUp: make(map[string][]PolicyFunction),
		policies: make(map[string]Policy),
	}
}

func (p *PolicyStore) GetPolicyFunction(lookUpName string, policyName string) (string, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	functions, ok := p.lookUp[lookUpName]
	if !ok {
		return "", &FunctionError{}
	}
	for _, function := range functions {
    if policyName == function.Policy {
			return function.InternalName, nil
		}
	}
	return "", &PolicyError{}
}

func (p *PolicyStore) AddPolicyFunction(lookUpName string, function PolicyFunction) string {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.lookUp == nil {
		p.lookUp = make(map[string][]PolicyFunction)
	}
	p.lookUp[lookUpName] = append(p.lookUp[lookUpName], function)
	return function.InternalName
}

func (p *PolicyStore) AddPolicy(policy Policy) string {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.policies == nil {
		p.policies = make(map[string]Policy)
	}	
	p.policies[policy.Name] = policy
	return policy.Name	
}

func (p *PolicyStore) AddPolicies(policies []Policy) {
	for _, policy := range policies {
		p.AddPolicy(policy)
	}
}

func (p *PolicyStore) BuildDeploymentForPolicy(function PolicyFunction,
	deployment *bootTypes.FunctionDeployment) bootTypes.FunctionDeployment {
	
		deployment.Service = deployment.Service + "-" + function.Policy
		(*deployment.Annotations)["policy"] = function.Policy
		(*deployment.Labels)["faas_function"] = deployment.Service

	return *deployment
}