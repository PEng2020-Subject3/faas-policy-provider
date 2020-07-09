// Package types contains definitions for public types
package types

type Policy struct {
	Name string
	Constraints []string
}

type PolicyFunction struct {
	InternalName string
	Policies []string
	Config string
}

type PolicyController interface {
	GetPolicyFunction(functionName string, policyName string) (string, error)
	// Return added function name
	AddPolicyFunction(lookUpName string, policyName string, function PolicyFunction) string
	AddPolicy(policy Policy) string
}

type PolicyStore struct {
	lookUp map[string][]PolicyFunction
	policies map[string]Policy
}

func (p PolicyStore) GetPolicyFunction(lookUpName string, policyName string) (string, error) {
	functions, ok := p.lookUp[lookUpName]
	if !ok {
		return "", &FunctionError{}
	}
	for _, function := range functions {
    if (StringInSlice(policyName, function.Policies)) {
			return function.InternalName, nil
		}
	}
	return "", &PolicyError{}
}

func (p PolicyStore) AddPolicyFunction(lookUpName string, policyName string, function PolicyFunction) string {
	if p.lookUp == nil {
		p.lookUp = make(map[string][]PolicyFunction)
	}
	p.lookUp[lookUpName] = append(p.lookUp[lookUpName], function)
	return function.InternalName
}

func (p PolicyStore) AddPolicy(policy Policy) string {
	if p.policies == nil {
		p.policies = make(map[string]Policy)
	}	
	p.policies[policy.Name] = policy
	return policy.Name
}