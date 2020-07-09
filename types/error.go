package types

type FunctionError struct{}
type PolicyError struct{}

func (f *FunctionError) Error() string {
    return "No function found"
}

func (f *PolicyError) Error() string {
    return "No policy found"
}