package sbom

import "fmt"

func (i *Identifier) flatString() string {
	return fmt.Sprintf("bomsquad.protobom.Node.identifiers[%s]:%s", i.Type, i.Value)
}
