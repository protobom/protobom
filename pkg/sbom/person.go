package sbom

import (
	"errors"
	"fmt"

	"github.com/protobom/protobom/pkg/formats/spdx"
)

// ErrPersonIsOrgAndSoftwareAgent is returned by Person.Validate when an
// entity claims to be both an organization and a piece of software. The two
// are different kinds of actor, and formats that tell them apart have no way
// to write something that is both.
var ErrPersonIsOrgAndSoftwareAgent = errors.New("person cannot be both an organization and a software agent")

// Validate returns an error when the person describes an actor that cannot
// exist.
func (p *Person) Validate() error {
	if p.IsOrg && p.IsSoftwareAgent {
		return fmt.Errorf("%w: %q", ErrPersonIsOrgAndSoftwareAgent, p.Name)
	}
	return nil
}

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
	if p.IsSoftwareAgent {
		s += "a(true)"
	}
	if p.Email != "" {
		s += fmt.Sprintf("email(%s)", p.Email)
	}
	if p.Url != "" {
		s += fmt.Sprintf("url(%s)", p.Url)
	}
	if p.Phone != "" {
		s += fmt.Sprintf("p(%s)", p.Phone)
	}
	// An empty contact list and no contact list are the same statement, so
	// they must produce the same string: a copy of a person initializes the
	// list and still has to be equal to its original.
	if len(p.Contacts) > 0 {
		s += "c("
		for _, c := range p.Contacts {
			s += c.flatString()
		}
		s += ")"
	}
	return s
}

// Copy returns a new Person pointer which is a duplicate of Person p. The copy is
// recursive into the Contacts array.
func (p *Person) Copy() *Person {
	np := &Person{
		Name:            p.Name,
		IsOrg:           p.IsOrg,
		IsSoftwareAgent: p.IsSoftwareAgent,
		Email:           p.Email,
		Url:             p.Url,
		Phone:           p.Phone,
		Contacts:        []*Person{},
	}
	for _, contact := range p.Contacts {
		np.Contacts = append(np.Contacts, contact.Copy())
	}
	return np
}
