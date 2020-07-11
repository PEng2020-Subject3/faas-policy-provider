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
	Limits 									*fTypes.FunctionResources `yaml:"limits"`
	Requests 								*fTypes.FunctionResources `yaml:"requests"`
	ReadOnlyRootFilesystem 	*bool `yaml:"readOnlyRootFilesystem"`
	Namespace 							*string `yaml:"namespace,omitempty"`
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
		
		if deployment.Annotations == nil {
			deployment.Annotations = new(map[string]string)
		}		

		policy, _ := p.GetPolicy(function.Policy) // TODO: Error Handling
		
		log.Info(1)
		if policy.Annotations != nil {
			MergeMap(*deployment.Annotations, *policy.Annotations)
		}	
		log.Info(2)
		if policy.EnvVars != nil {
			MergeMap(deployment.EnvVars, *policy.EnvVars)
		}
		log.Info(3)
		if policy.Labels != nil {
			if deployment.Labels == nil {
				deployment.Labels = policy.Labels
			} else {
				MergeMap(*deployment.Labels, *policy.Labels)
			}	
		}	
		log.Info(4)
		if policy.Constraints != nil {
			deployment.Constraints = append(deployment.Constraints, *policy.Constraints...)		
		}	
		log.Info(5)
		if policy.Secrets != nil {
			deployment.Secrets = append(deployment.Secrets, *policy.Secrets...)		
		}	
		log.Info(6)
		if policy.Limits != nil {
			deployment.Limits = policy.Limits
		}
		log.Info(7)
		if policy.Requests != nil {
			deployment.Requests = policy.Requests
		}
		log.Info(8)
		if policy.ReadOnlyRootFilesystem != nil {
			deployment.ReadOnlyRootFilesystem = *policy.ReadOnlyRootFilesystem
		}
		log.Info(9)
		if policy.Namespace != nil {
			deployment.Namespace = *policy.Namespace
		}

		// Keep these last to override any illegal statements
		(*deployment.Annotations)["policy"] = function.Policy
		(*deployment.Annotations)["parent_function"] = deployment.Service		
		(*deployment.Labels)["faas_function"] = name

		function.InternalName = name
		deployment.Service = name

		log.Info(deployment)

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
	log.Infof("Attemtping to delete %s from policy cache", f.Service) 
	if *f.Annotations == nil {
		log.Infof("no annotations found for %s", f.Service) 
		return
	}
	parent_name, ok := (*f.Annotations)["parent_function"]; if !ok {
		log.Warnf("no parent_function found for %s", f.Service) 
		return
	}
	policy, ok := (*f.Annotations)["policy"]; if !ok {
		log.Warnf("no policy found for %s", f.Service) 
		return
	}

	log.Infof("Attempting to delete %s from policy cache %s", parent_name, policy)	

	i, _, err := p.GetPolicyFunction(parent_name, policy);
	if err != nil {
		log.Warnf("no policy function found for %s with %s", parent_name, policy) 
		return
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	if err == nil {
		log.Infof("delete function from policy cache: lookup for %s with %s", parent_name, f.Service) 
		p.lookUp[parent_name] = append(p.lookUp[parent_name][:i], p.lookUp[parent_name][i+1:]...) // delete
		return
	}

	log.Infof("Not able to delete %s from policy cache %s", parent_name, policy)	
}