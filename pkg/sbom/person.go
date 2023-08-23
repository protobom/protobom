package sbom

import (
	"fmt"

	"github.com/bom-squad/protobom/pkg/formats/spdx"
)

// ToSPDX2ClientString converts the person to an SPDX actor string (not valid for
// an SBOM but to feed into the SPDX go-tools).
func (p *Person) ToSPDX2ClientString() string {
	supplierString := p.Name
	if p.Email != "" {
		supplierString = fmt.Sprintf("%s (%s)", p.Name, p.Email)
	}
	return supplierString
}

// ToSPDX2ClientOrg returns a string representing the type of actor to
// use in the SPDX go-tools, basically it will returns "Organization" or "Person"
func (p *Person) ToSPDX2ClientOrg() string {
	if p.IsOrg {
		return spdx.Organization
	} else {
		return spdx.Person
	}
}

func (p *Person) flatString() string {
	s := fmt.Sprintf("n(%s)o(%v)", p.Name, p.IsOrg)
	if p.Email != "" {
		s += fmt.Sprintf("email(%s)", p.Email)
	}
	if p.Url != "" {
		s += fmt.Sprintf("url(%s)", p.Url)
	}
	if p.Phone != "" {
		s += fmt.Sprintf("p(%s)", p.Phone)
	}
	if p.Contacts != nil {
		s += "c("
		for _, c := range p.Contacts {
			s += c.flatString()
		}
		s += ")"
	}
	return s
}
