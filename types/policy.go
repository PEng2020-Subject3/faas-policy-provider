// Package types contains definitions for public types
package types

import(
	"sync"
	fTypes "github.com/openfaas/faas-provider/types"

	log "github.com/sirupsen/logrus"
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
	GetPolicyFunction(functionName string, policyName string) (int, string, error)
	// Return added function name
	AddPolicyFunction(lookUpName string, function PolicyFunction) string
	AddPolicy(policy Policy) string
	AddPolicies(policies []Policy)
	GetPolicy(policyName string) (Policy, bool)
	ReloadFromCache(functions []*fTypes.FunctionDeployment)
	BuildDeployment(function *PolicyFunction, deployment *fTypes.FunctionDeployment) (*fTypes.FunctionDeployment, *PolicyFunction)
	DeleteFunction(function *fTypes.FunctionDeployment)
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

func (p *PolicyStore) GetPolicyFunction(lookUpName string, policyName string) (int, string, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()
	log.Infof("get policy function policy %s", lookUpName) 

	functions, ok := p.lookUp[lookUpName]
	if !ok {
		return -1, "", &FunctionError{}
	}
	for i, function := range functions {
    if policyName == function.Policy {
			return i, function.InternalName, nil
		}
	}
	return -1, "", &PolicyError{}
}

func (p *PolicyStore) AddPolicyFunction(lookUpName string, function PolicyFunction) string {
	p.lock.Lock()
	defer p.lock.Unlock()
	log.Infof("add function to policy cache: lookup for %s with %s", lookUpName, function.InternalName) 

	if p.lookUp == nil {
		p.lookUp = make(map[string][]PolicyFunction)
	}
	p.lookUp[lookUpName] = append(p.lookUp[lookUpName], function)
	return function.InternalName
}

func (p *PolicyStore) AddPolicy(policy Policy) string {
	p.lock.Lock()
	defer p.lock.Unlock()
	log.Infof("add policy %s", policy.Name) 


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
func (p *PolicyStore) GetPolicy(policyName string) (Policy, bool) {
	p.lock.RLock()
	defer p.lock.RUnlock()
	policy, ok := p.policies[policyName]
	return policy, ok
}

func (p *PolicyStore) BuildDeployment(function *PolicyFunction,
	deployment *fTypes.FunctionDeployment) (*fTypes.FunctionDeployment, *PolicyFunction) {
		name := deployment.Service + "-" + function.Policy	
		
		if *(deployment.Annotations) == nil {
			*(deployment.Annotations) = *new(map[string]string)
		}

		(*deployment.Annotations)["policy"] = function.Policy
		(*deployment.Annotations)["parent_function"] = deployment.Service		
		(*deployment.Labels)["faas_function"] = name

		function.InternalName = name
		deployment.Service = name

		return deployment, function
}

func (p *PolicyStore) ReloadFromCache(functions []*fTypes.FunctionDeployment) {	
	log.Info("reload policy cache ...") 
	for _, f := range functions {
		
		if *f.Annotations == nil {
			log.Infof("no annotations found for %s", f.Service) 
			return
		}
				
		if fPolicy, ok := (*f.Annotations)["policy"]; ok {
			if _, ok := p.policies[fPolicy]; ok {
				parent_name, ok := (*f.Annotations)["parent_function"]
				if ok { 
					p.AddPolicyFunction(parent_name, PolicyFunction{f.Service, fPolicy})
				}
			}
		}
	}
	log.Info("policy cache reloaded succesfully") 
}

func (p *PolicyStore) DeleteFunction(f *fTypes.FunctionDeployment) {
	p.lock.Lock()
	defer p.lock.Unlock()

	log.Infof("attempting to delete function from policy cache: %s", f.Service) 
	
	if parent_name, ok := (*f.Annotations)["parent_function"]; ok {
		if i, name, err := p.GetPolicyFunction(parent_name, (*f.Annotations)["policy"]); err == nil {
			log.Infof("delete function from policy cache: lookup for %s with %s", parent_name, f.Service) 
			p.lookUp[name] = append(p.lookUp[name][:i], p.lookUp[name][i+1:]...) // delete
		}
	} else {
		if len(p.lookUp[f.Service]) == 0 {
			log.Infof("no policies for %s remaining", f.Service) 
			log.Infof("delete parent function  %s from policy cache", f.Service) 
			delete(p.lookUp, f.Service)
		}
	}
}