# SBOM translation analysis

## Background
This file documents the analysis and decisions taken througout the SBOM translation project.

- config.input = cycloneDX/spdx
- config.output = spdx/cycloneDX (opposite of config.input)
- config.spdx = all configuration regarding the spdx sbom
- config.cycloneDX = all configuration regarding the cycloneDX sbom
- spdx = the input or output spdx
- cycloneDX = the input or output cycloneDX

## CycloneDX to SPDX

### Utilities
#### strings to single line of text - normalize2line()
- spdx defines several field formats as a single line of text, while CycloneDx defines it as a string. To handle the case of a multi-line cycloneDX version need to nornalize.
- normalize2line shall switch all \n or \n\l to a config substring, default to & (taking the notion of REST APIs). The substring can be modified by setting:
    - config.spdx.str2lineSeparator

### [SPDX document creation information section](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/)

#### [specVersion](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#61-spdx-version-field)

- spdx.specVersion = config.spdx.specVersion, default to "SPDX-2.3"
- translationNotes.cycloneDX.bomFormat = cycloneDX.bomFormat
- translationNotes.cycloneDX.specVersion = cycloneDX.specVersion

Links:
- [bomFormat](https://cyclonedx.org/docs/1.4/json/#bomFormat)
- [specVersion](https://cyclonedx.org/docs/1.4/json/#specVersion)

#### [DataLicense](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field)

spdx.dataLicense = "CC0-1.0"

Verification: spdx.dataLicense == "CC0-1.0"

#### [SPDXID](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field)
This is supposed to be a unique identifier to the spdx document.

- spdx.SPDXID = config.spdx.SPDXID, default to:

    - "SPDX"+ date+time + cycloneDX.serialNumber
    - date + time in the standard UTC format as described [here](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field)

#### [documentName](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field)

- spdx.name = config.spdx.name, default to cycloneDX.metadata.component.name + cycloneDX.metadata.component.version

#### [documentNamespace](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field)

- spdx.documentNamespace = "https://spdx.org/spdxdocs/" + name + '-' + {version 4 random UUID}

TBD: check the difference between documentNamespace and SPDXID

Verification: verify spdx.documentNamespace is a valid uri

#### [External document references](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#66-external-document-references-field)

This field will not be populated. It is intended for other spdx documents, and these are not expected in a cycloneDX document.

Notes:
- In the future this filed can be populated from cycloneDX.components.externalReferences if the externalReference type is bom and it is an SPDX document. This requires access to the SPDX document.
- the cyclondDX.externalReferences field has a different meaning (it is a list of external relevan docs, and not a list of references used inside the SBOM)

#### [License list version](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#67-license-list-version-field)

- spdx.licenseListVersion = config.spdx.licenseListVersion, default to not including this element at all.

Notes:
- Future feature: May be calculated from license info present in ths CycloneDX

#### [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field)

The spdx.creator is a list of strings as described in the link.

- initialize spdx.creator to [] and append the following:
- for author in cycloneDX.metadata.authors
    - append "Creator: Person: {author.name} ({author.email})"
- append "Creator: Organization: {cycloneDX.metadata.manufacture.name} ({cycloneDX.metadata.manufacture.contact[0].email})
- append "Creator: Organization: {cycloneDX.metadata.supplier.name} ({cycloneDX.metadata.supplier.contact[0].email})


Notes:
- information lost:
    - cycloneDX.metadata.authors.phone
    - manufacture and supplier url
    - manufacture and supplier contacts: currently assumed to take only the first email. Another option is to have a list creators with all the contacts.
    - Missing in this schema a way to distinguish between the manufacture and supplier. It can be added through a string in the name in the lines of "Creator: Organization: manufacture:acme.inc
- options:
    - define in configuration and default to the above.
    - define configuration options such as whether to put all contacts as creators.

#### [Created](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field)

- spdx.created = conversion time if config.spdx.created == "conversion_time"
- spdx.created = cycloneDX.metadata.timeStamp if config.spdx.created == "original_time"

Notes:
- consider a global setting (for spdx.created and cycloneDX.metadata.timeStamp)
- Check if cycloneDX dictates a time-date structure and handle the case that it does not.

Verification: Verify time is UTC formatted.

#### [Creator Comment](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#610-creator-comment-field)

spdx.creatorComment = config.spdx.creatorComment, default to cycloneDX.metadata.tools as a JSON string.

Notes:
- consider an option to add a user string to the default

#### [Document Comment](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#611-document-comment-field)

- if config.spdx.documentCommentSetting == "config" then spdx.documentComment = config.spdx.documentComment
- if config.spdx.documentCommentSetting == "allCycloneDX" then spdx.documentComment = cycloneDX
    - consider: store as base64 or compressed JSON
- if config.spdx.documentCommentSetting == "CycloneDXMetadata" then spdx.documentComment = cycloneDX.metadata

Notes:
- Storing the whole cycloneDX can enable translation round trips. It may cause problems for spdx viewers, since probably this field is supposed to be displayed.

### [Package Information](https://spdx.github.io/spdx-spec/v2.3/package-information/)

For each componen in the CycloneDX create a packege information object.
Note that the only fields that are required for a cycloneDX package are type and name, thus the folowing conversion rules should handle the case that data is absent from the CycloneDX input.

CycloneDX represents all components as components with a type identifier.

- if cycloneDX.type == file - create a FileInformation object.
- else create a package, and store the type information in the Primary Package Purporse field. Following is a finer definition for all possible types **TBD**
    - application = A software application. Refer to https://en.wikipedia.org/wiki/Application_software for information about applications.
    - framework = A software framework. Refer to https://en.wikipedia.org/wiki/Software_framework for information on how frameworks vary slightly from libraries.
    - library = A software library. Refer to https://en.wikipedia.org/wiki/Library_(computing)
for information about libraries. All third-party and open source reusable components will likely be a library. If the library also has key features of a framework, then it should be classified as a framework. If not, or is unknown, then specifying library is RECOMMENDED.
    - container = A packaging and/or runtime format, not specific to any particular technology, which isolates software inside the container from software outside of a container through virtualization technology. Refer to https://en.wikipedia.org/wiki/OS-level_virtualization
    - operating-system = A software operating system without regard to deployment model (i.e. installed on physical hardware, virtual machine, image, etc) Refer to https://en.wikipedia.org/wiki/Operating_system
    - device = A hardware device such as a processor, or chip-set. A hardware device containing firmware SHOULD include a component for the physical hardware itself, and another component of type 'firmware' or 'operating-system' (whichever is relevant), describing information about the software running on the device.
    - firmware = A special type of software that provides low-level control over a devices hardware. Refer to https://en.wikipedia.org/wiki/Firmware
    - file = A computer file. Refer to https://en.wikipedia.org/wiki/Computer_file for information about files.


A component in cycloneDX has a components field, thus one can create a tree of components. When converting a CycloneDX to SPDX it is required to traverse all components, create for each packageInformation object.
- No deduping will be done; objects will differ by the PackageSPDXIdentifier
- **TBD** Traversing in REGO is a challenge


#### [Package name](https://spdx.github.io/spdx-spec/v2.3/package-information/#71-package-name-field)
spdx.packages[].packageName = cycloneDX.components[].name

#### [Package SPDX identifier](https://spdx.github.io/spdx-spec/v2.3/package-information/#72-package-spdx-identifier-field)
- if cycloneDX.components[].bomRef exists
spdx.packages[].PackageSPDXIdentifier = SPDXRef + cycloneDX.components[].bomRef

- else create an identifier: spdx.packages[].PackageSPDXIdentifier = SPDXRef + packageName+packageVersion + uniqeSalt
    - uniqeSalt is required only it the package exists more than once.

#### [Package version](https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field)

Note:

- If cycloneDX does not hava a version, spdx will aslo not have the version (the component will not be created)

spdx.packages[].packageVersion = normalize2line(cycloneDX.components[].version)

#### [Package file name](https://spdx.github.io/spdx-spec/v2.3/package-information/#74-package-file-name-field)

Notes:
- Package file name is not defined in CycloneDX, so we default to not populating this field, bus support populating it from a specific property.
- packageFileName is a single line of text - use normalize2line.

if config.spdx.PackageFileName.CycloneDXProperty exist and is not null:

spdx.packages[].packageFileName = cycloneDX.components[].properties[_] where the property name equals config.spdx.packageFileNameCycloneDXProperty

#### [Package supplier](https://spdx.github.io/spdx-spec/v2.3/package-information/#75-package-supplier-field)

**TBD** Reconsider:
- maybe better to use the spdx author or publisher fields for the supplier, and use the cycloneDX supplier info to populate the Package Originator fields.


Notes:

- The packagSupplier is a single line of text - use normalize2line.
- The packageSupplier can be one of an organization or person. CycloneDX defines the supplier to be the organzation but supports also a contacts sub component.
- SPDX suggest the use of "NOASSERTION" in a few cases. In SBOM conversion the converter will not create this field if it cannot make an assertion.
- if cycloneDX component.supplier has additional url and contact infromation - this information will be lost in the conversion.
- If the cycloneDX has many contacts the current strategy suggested is to take the first, but anther strategy could be to take the fullest.


if cycloneDX.components[].supplier exists:
- if there is a name:
    - spdx.packages[].packageSupplier = "Organization:" + normalize2line(cycloneDX.components[].supplier.name) + '('+ email + ')' of the first contact.
- if there is no name but contacts are give
    - packageSupplier = "Person:" + cycloneDX.components[].supplier.contacts[_].name + '('+ email + ')' of the first contact.


#### [Package originator](https://spdx.github.io/spdx-spec/v2.3/package-information/#76-package-originator-field)

See above - in package supplier field.

spdx.packages[].
#### [Package download location](https://spdx.github.io/spdx-spec/v2.3/package-information/#77-package-download-location-field)

- since cycloneDX does not have this information:
    - spdx.packages[].packageDownloadLoacation = "NOASSERTION"
- If cycloneDX component includes a pedigree object with commit info that includes a url, then use this url:
    - packageDownloadLoacation = "PackageDownloadLocation:"+config.spdx.packages.sourceControlPrefix + url
    - ensure url starts with //
    - the source control prefix parameter should have a scope of the whole spdx document, since it is probably for internal packages only.
    - Note that golang packages are pulled directly from source control and in this case the prefix should be according the the Golang package url. This feature is left for the future.


#### [Files analyzed](https://spdx.github.io/spdx-spec/v2.3/package-information/#78-files-analyzed-field)
**TBD**
spdx.packages[].
#### [Package verification code](https://spdx.github.io/spdx-spec/v2.3/package-information/#79-package-verification-code-field)

Notes:
- The packageVerificationCode is a hash of the sorted file-hash-list of a package. This infromation does not explicitly exist in CycloneDX.
- The field is mandatory, but not found on syft generated spdx.
- The solution for this complexity is to have a configuration. **TBD** Decide if default is not to enforce the field as mandatory.
- The options that it can be included:
    - there is a hashes item in the cycloneDX component that is known to follow the SPDX hash calculation algoritm.
    - The CycloneDX component includes subcomponents with sha-1 hashes of all components (which could be done using a dependecy graph or using the components field within the component). Both are not very popular today, and thus this feature is left for future use.

Implementation:

if config.spdx.components.requirePackageVerificationCodes == True then spdx.packages[].packegeVerificationCode = the first sha-1 hash in cycloneDX.components[].hashes[].

Else fail the conversion.



#### [Package checksum](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field)

Notes:
- This field is a bit more flexible (and less defined) that the verification code.

-If config.spdx.dontIncludePackageChecksum == True then do not create this field.

- Else generate the field by itrating over the cycloneDX.components[].hashes array:
    - if alg is in ["SHA-1", "MD5", "SHA-256"] then add a package checksum line by : "PackageChecksum:" + alg after removing the hyphen + content

#### [Package home page](https://spdx.github.io/spdx-spec/v2.3/package-information/#711-package-home-page-field)

- This field is not explicitly included in the cycloneDX file.
- Since this field is optional - do not create this object.
- options to populate in the future **TBD**:
    - Use supplier url field if exists

#### [Source information](https://spdx.github.io/spdx-spec/v2.3/package-information/#712-source-information-field)

This field in optional.

- if config.spdx.packages.sourceInformation = "CycloneDXpedigree"
    - Then spdx.packages[].sourceInformation = toString(cycloneDX.components[].pedigree)
- else do not include this field.

#### [Concluded license](https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field)

Need to calculate from cycloneDX.components[].licenses a <license-set> string (see spdx doc).

**TBD** Need to define the algorithm of creating a license-set

spdx.packages[].
#### [All licenses information from files](https://spdx.github.io/spdx-spec/v2.3/package-information/#714-all-licenses-information-from-files-field)


- If CycloneDX.components[].licenses == null or does not exist then spdx.packages[].allLicenseInfromation = config.spdx.packages.noLicenseDefault
    - noLicenseDefault is one of ["NONE", "NOASSERTION"]
    - if it is not set - the default is "NONE"

Otherwise **TBD** It seems from the standard that either a short form or a license name should appear, in addition to an expression. That is not what I see in syft or our CycloneDXs. Need to verify.
{
CycloneDX has two options to describe licenses:
- Option 1: A list of license objects.
    -
- Option 2: A list of expressions
    - In this case - create a list of short form identifiers by parsing the expressions and extracting short-form license from them.
    - If unkown license is found - by default - include it **TBD** Log unknowd refs.
        - if config.spdx.packages.enforceLicesesList == True fail the conversion.
}

#### [Declared license](https://spdx.github.io/spdx-spec/v2.3/package-information/#715-declared-license-field)
**TBD** Need to know which license is the declared. I suggest the following options:
- Take the first license from the licenses object.
- Take the most restrictive
- The above by configuration. At the first stage the configuration can be a  list of licesnes ordered by priority.

#### [Comments on license](https://spdx.github.io/spdx-spec/v2.3/package-information/#716-comments-on-license-field)

- Either config.spdx.packages.defaultLicensesComment (if exists)
- Or toString(cycloneDX.components[].licenses)

#### [Copyright text](https://spdx.github.io/spdx-spec/v2.3/package-information/#717-copyright-text-field)

- if cycloneDX.components[].copyright is not empty
    - spdx.packages[].copyrightText = cycloneDX.components[].copyright
- else spdx.packages[].copyrightText = config.spdx.packages.noCopyrightTextDefault
    - noCopyrightTextDefault is one of ["NONE", "NOASSERTION"]
    - if it is not set - the default is "NONE"

#### [Package summary description](https://spdx.github.io/spdx-spec/v2.3/package-information/#718-package-summary-description-field)

spdx.packages[].packageSummaryDescription = cycloneDX.components[].description

#### [Package detailed description](https://spdx.github.io/spdx-spec/v2.3/package-information/#719-package-detailed-description-field)
Do not create this object - there is no equivalent in CycloneDX.

#### [Package comment](https://spdx.github.io/spdx-spec/v2.3/package-information/#720-package-comment-field)

- if config.spdx.packages.packageComment = "properties" then spdx.packages[].packageComment = toString(cycloneDX.components[].properties)
- else do not include the object.

#### [External reference](https://spdx.github.io/spdx-spec/v2.3/package-information/#721-external-reference-field)

spdx.packages[].
#### [External reference comment](https://spdx.github.io/spdx-spec/v2.3/package-information/#722-external-reference-comment-field)
spdx.packages[].
#### [Package attribution text](https://spdx.github.io/spdx-spec/v2.3/package-information/#723-package-attribution-text-field)
spdx.packages[].
#### [Primary Package Purpose](https://spdx.github.io/spdx-spec/v2.3/package-information/#724-primary-package-purpose-field)
spdx.packages[].primaryPackagePurpose = cycloneDX.components[].type

#### [Release Date](https://spdx.github.io/spdx-spec/v2.3/package-information/#725-release-date)
spdx.packages[].
#### [Built Date](https://spdx.github.io/spdx-spec/v2.3/package-information/#726-built-date)
spdx.packages[].
#### [Valid Until Date](https://spdx.github.io/spdx-spec/v2.3/package-information/#727-valid-until-date)
spdx.packages[].


### [File Information](https://spdx.github.io/spdx-spec/v2.3/file-information/)

#### [File name](https://spdx.github.io/spdx-spec/v2.3/file-information/#81-file-name-field)

#### [File SPDX identifier](https://spdx.github.io/spdx-spec/v2.3/file-information/#82-file-spdx-identifier-field)

#### [File type](https://spdx.github.io/spdx-spec/v2.3/file-information/#83-file-type-field)
#### [File checksum](https://spdx.github.io/spdx-spec/v2.3/file-information/#84-file-checksum-field)
#### [Concluded license](https://spdx.github.io/spdx-spec/v2.3/file-information/#85-concluded-license-field)
#### [License information in file](https://spdx.github.io/spdx-spec/v2.3/file-information/#86-license-information-in-file-field)
#### [Comments on license](https://spdx.github.io/spdx-spec/v2.3/file-information/#87-comments-on-license-field)
#### [Copyright text](https://spdx.github.io/spdx-spec/v2.3/file-information/#88-copyright-text-field)
#### [Artifact of project name](https://spdx.github.io/spdx-spec/v2.3/file-information/#89-artifact-of-project-name-field-deprecated)
#### [Artifact of project homepage field (deprecated)]()
#### [Artifact of project uniform resource identifier field (deprecated)]()
#### [File comment](https://spdx.github.io/spdx-spec/v2.3/file-information/#812-file-comment-field)
#### [File notice](https://spdx.github.io/spdx-spec/v2.3/file-information/#813-file-notice-field)
#### [File contributor](https://spdx.github.io/spdx-spec/v2.3/file-information/#814-file-contributor-field)
#### [File attribution](https://spdx.github.io/spdx-spec/v2.3/file-information/#815-file-attribution-text-field)
#### [File dependencies field (deprecated)]()



### [Snippet Information](https://spdx.github.io/spdx-spec/v2.3/snippet-information/)

#### [Snippet SPDX identifier](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#91-snippet-spdx-identifier-field)
#### [Snippet from file SPDX identifier](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#92-snippet-from-file-spdx-identifier-field)
#### [Snippet byte range](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#93-snippet-byte-range-field)
#### [Snippet line range](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#94-snippet-line-range-field)
#### [Snippet concluded license](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#95-snippet-concluded-license-field)
#### [License information in snippet](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#96-license-information-in-snippet-field)
#### [Snippet comments on license](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#97-snippet-comments-on-license-field)
#### [Snippet copyright text](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#98-snippet-copyright-text-field)
#### [Snippet comment](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#99-snippet-comment-field)
#### [Snippet name](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#910-snippet-name-field)
#### [Snippet attribution](https://spdx.github.io/spdx-spec/v2.3/snippet-information/#911-snippet-attribution-text-field)



### [Other licensing information detected section](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/)

#### [License identifier](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/)
#### [Extracted text](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#102-extracted-text-field)
#### [License name](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#103-license-name-field)
#### [License cross reference](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#104-license-cross-reference-field)
#### [License comment](https://spdx.github.io/spdx-spec/v2.3/other-licensing-information-detected/#105-license-comment-field)

### [relationships-between-SPDX-elements](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/)
#### [Relationship](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/)
#### [Relationship comment](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/#112-relationship-comment-field)


## SPDX to CycloneDX
