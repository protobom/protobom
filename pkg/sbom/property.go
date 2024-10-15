package sbom

import "fmt"

func NewProperty() *Property {
	return &Property{}
}

// flatString returns the flattened string representing the property and its data
func (p *Property) flatString() string {
	return fmt.Sprintf("n(%s)d(%s)", p.Name, p.Data)
}

// Copy returns a pointer to a new property that is a copy of the original property
func (p *Property) Copy() *Property {
	return &Property{
		Name: p.Name,
		Data: p.Data,
	}
}
